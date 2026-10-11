import AppKit
import ServiceManagement
import SwiftUI

enum Phase: Equatable {
    case connecting
    case failed(String)
    case pairing(code: String)
    case noVault
    case locked
    case unlocked
}

/// What the unlocked popover is showing.
enum Screen: Equatable {
    case search
    case add
    case changePassword(Entry)
}

/// Everything the menu shows, and the two daemon connections behind it: one
/// for requests, one subscribed to approval questions.
@MainActor
final class AppModel: ObservableObject {
    @Published private(set) var phase: Phase = .connecting
    @Published private(set) var status: Status?
    @Published private(set) var entries: [Entry] = []
    @Published private(set) var watching = false
    @Published private(set) var notice: String?
    @Published var query = ""
    @Published var selectedID: Entry.ID?
    @Published var screen: Screen = .search
    @Published var launchAtLogin = SMAppService.mainApp.status == .enabled
    /// The one entry whose password is on screen, if any.
    @Published private(set) var revealed: (id: Entry.ID, password: String)?

    private let paths = Paths.default
    private var identity: Identity?
    private var client: OpenPassClient?
    private var watcher: OpenPassClient?
    private var statusTimer: Timer?
    private var noticeTask: Task<Void, Never>?
    private var revealTask: Task<Void, Never>?
    static let revealFor: TimeInterval = 30
    private let approvals = ApprovalPresenter()

    var filtered: [Entry] {
        entries.filter { $0.matches(query) }
            .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }

    /// The highlighted row: the chosen one if it is still in the results,
    /// otherwise the top result, so Return always copies something visible.
    func selection(in results: [Entry]) -> Entry.ID? {
        if let selectedID, results.contains(where: { $0.id == selectedID }) { return selectedID }
        return results.first?.id
    }

    var menuBarIcon: String {
        switch phase {
        case .unlocked: return "lock.open.fill"
        case .failed: return "exclamationmark.lock.fill"
        default: return "lock.fill"
        }
    }

    init() {
        Task { await start() }
        // status does not touch the autolock timer, so polling it cannot keep
        // the vault open.
        statusTimer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            Task { @MainActor in await self?.refreshStatus() }
        }
    }

    // MARK: Connecting

    func start() async {
        phase = .connecting
        do {
            if identity == nil {
                identity = try Identity.loadOrCreate(at: paths.identity, name: "openpass menu bar", kind: "cli")
            }
            client?.close()
            client = nil

            let c = try await OpenPassClient.connect(paths: paths, identity: identity!)
            let conn = c.conn
            conn.onClose = { [weak self] in
                Task { @MainActor in self?.connectionLost(conn) }
            }
            client = c

            guard try await ensurePaired(c) else { return }
            await refreshStatus()
            await startWatcher()
        } catch {
            phase = .failed(error.localizedDescription)
        }
    }

    /// Returns true once approved. A pending client cannot make any signed
    /// call, so this keeps re-asking until someone approves it.
    private func ensurePaired(_ c: OpenPassClient) async throws -> Bool {
        while true {
            switch try await c.pair() {
            case .approved:
                return true
            case .pending(let code):
                phase = .pairing(code: code)
                try await Task.sleep(nanoseconds: 2_000_000_000)
                if client?.conn !== c.conn { return false }
            }
        }
    }

    private func connectionLost(_ conn: DaemonConnection) {
        // A connection start() replaced on purpose is not a loss.
        guard client?.conn === conn else { return }
        client = nil
        phase = .connecting
        Task {
            try? await Task.sleep(nanoseconds: 1_000_000_000)
            await start()
        }
    }

    // MARK: Approvals

    /// Takes the place of `openpass watch`: without a subscriber, a client
    /// whose policy is "prompt" can never read a secret.
    private func startWatcher() async {
        guard watcher == nil, let identity else { return }
        do {
            let w = try await OpenPassClient.connect(paths: paths, identity: identity)
            w.conn.onNotification = { [weak self] method, params in
                guard method == "approval.requested", let req = ApprovalRequest(params) else { return }
                Task { @MainActor in self?.ask(req) }
            }
            let conn = w.conn
            conn.onClose = { [weak self] in
                Task { @MainActor in self?.watcherLost(conn) }
            }
            try await w.subscribe()
            watcher = w
            watching = true
        } catch {
            watching = false
            Task {
                try? await Task.sleep(nanoseconds: 3_000_000_000)
                await startWatcher()
            }
        }
    }

    private func watcherLost(_ conn: DaemonConnection) {
        guard watcher?.conn === conn else { return }
        watcher = nil
        watching = false
        Task {
            try? await Task.sleep(nanoseconds: 1_000_000_000)
            await startWatcher()
        }
    }

    private func ask(_ req: ApprovalRequest) {
        approvals.enqueue(req) { [weak self] allow, remember in
            guard let w = self?.watcher else { return }
            Task {
                try? await w.respond(id: req.id, allow: allow, ttlSeconds: allow ? remember : 0)
            }
        }
    }

    // MARK: Vault

    func refreshStatus() async {
        guard let client else { return }
        if case .pairing = phase { return }
        do {
            let s = try await client.status()
            status = s
            let next: Phase = !s.vaultPresent ? .noVault : (s.locked ? .locked : .unlocked)
            if next != .unlocked {
                entries = []
                hidePassword()
                // A half-filled form must not survive a lock and reappear,
                // password and all, after the next unlock.
                screen = .search
            }
            if phase != next {
                phase = next
                if next == .unlocked { await refreshEntries() }
            }
        } catch {
            handle(error)
        }
    }

    /// vault.list resets the autolock timer, so this runs only when someone is
    /// looking at the menu, never on a timer.
    func refreshEntries() async {
        guard let client, phase == .unlocked else { return }
        do {
            entries = try await client.list()
        } catch {
            handle(error)
        }
    }

    func unlock(password: String) async -> String? {
        guard let client else { return "Not connected to openpassd." }
        do {
            try await client.unlock(password: password)
            await refreshStatus()
            return nil
        } catch let error as OpenPassError where error.isCode(OpenPassError.badPassword) {
            return "Wrong password."
        } catch {
            return error.localizedDescription
        }
    }

    func lock() async {
        guard let client else { return }
        do {
            try await client.lock()
            query = ""
            await refreshStatus()
        } catch {
            handle(error)
        }
    }

    func copyPassword(_ entry: Entry) async {
        guard let client else { return }
        do {
            let password = try await client.password(id: entry.id)
            Clipboard.copySecret(password)
            show("Copied the password for \(entry.name). Clears in \(Int(Clipboard.clearAfter))s.")
        } catch {
            handle(error)
        }
    }

    /// Shows an entry's password in its row, or hides it if it is already
    /// showing. One at a time, and only briefly: a password left on screen is
    /// one anyone walking past can read.
    func toggleReveal(_ entry: Entry) async {
        if revealed?.id == entry.id {
            hidePassword()
            return
        }
        guard let client else { return }
        do {
            let password = try await client.password(id: entry.id)
            revealed = (entry.id, password)
            revealTask?.cancel()
            revealTask = Task {
                try? await Task.sleep(nanoseconds: UInt64(Self.revealFor * 1_000_000_000))
                if !Task.isCancelled { revealed = nil }
            }
        } catch {
            handle(error)
        }
    }

    func hidePassword() {
        revealTask?.cancel()
        revealed = nil
    }

    /// Adds an entry. Returns an error message for the form, or nil on success.
    ///
    /// A generated password is copied afterwards, as `openpass add -gen` does:
    /// the next thing anyone does with it is paste it into the site.
    func add(name: String, username: String, password: String, url: String, notes: String,
             generated: Bool) async -> String? {
        guard let client else { return "Not connected to openpassd." }
        do {
            let id = try await client.add(name: name, username: username, password: password,
                                          urls: url.isEmpty ? [] : [url], notes: notes)
            await refreshEntries()
            query = ""
            selectedID = id
            screen = .search
            if generated {
                Clipboard.copySecret(password)
                show("Added \(name) and copied its password. Clears in \(Int(Clipboard.clearAfter))s.")
            } else {
                show("Added \(name).")
            }
            return nil
        } catch {
            return formError(error)
        }
    }

    func changePassword(_ entry: Entry, to password: String, generated: Bool) async -> String? {
        guard let client else { return "Not connected to openpassd." }
        do {
            try await client.changePassword(id: entry.id, to: password)
            selectedID = entry.id
            screen = .search
            if generated {
                Clipboard.copySecret(password)
                show("Changed the password for \(entry.name) and copied it. Clears in \(Int(Clipboard.clearAfter))s.")
            } else {
                show("Changed the password for \(entry.name).")
            }
            return nil
        } catch {
            return formError(error)
        }
    }

    /// Whether an entry already has this name. Not an error, since the vault
    /// allows it, but `openpass get <name>` will then call it ambiguous.
    func nameTaken(_ name: String) -> Bool {
        let trimmed = name.trimmingCharacters(in: .whitespaces)
        return entries.contains { $0.name.caseInsensitiveCompare(trimmed) == .orderedSame }
    }

    private func formError(_ error: Error) -> String {
        if let e = error as? OpenPassError, e.isCode(OpenPassError.vaultLocked) {
            handle(error)
            return "The vault locked."
        }
        return error.localizedDescription
    }

    func copyUsername(_ entry: Entry) {
        Clipboard.copyPlain(entry.username)
        show("Copied the username for \(entry.name).")
    }

    func setLaunchAtLogin(_ on: Bool) {
        do {
            if on {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
        } catch {
            show("Could not change the login item: \(error.localizedDescription)")
        }
        launchAtLogin = SMAppService.mainApp.status == .enabled
    }

    private func handle(_ error: Error) {
        if let e = error as? OpenPassError {
            if e.isCode(OpenPassError.vaultLocked) {
                phase = .locked
                entries = []
                hidePassword()
                screen = .search
                return
            }
            if case .disconnected = e { return } // onClose reconnects
        }
        show(error.localizedDescription)
    }

    private func show(_ message: String) {
        notice = message
        noticeTask?.cancel()
        noticeTask = Task {
            try? await Task.sleep(nanoseconds: 4_000_000_000)
            if !Task.isCancelled { notice = nil }
        }
    }
}
