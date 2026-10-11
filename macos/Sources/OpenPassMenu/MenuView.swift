import SwiftUI

struct MenuView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            content
                .padding(12)

            if let notice = model.notice {
                Divider()
                Text(notice)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
            }

            Divider()
            Footer()
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
        }
        .frame(width: 340)
        .task { await model.refreshStatus(); await model.refreshEntries() }
    }

    @ViewBuilder private var content: some View {
        switch model.phase {
        case .connecting:
            HStack {
                ProgressView().controlSize(.small)
                Text("Connecting to openpassd…")
            }
        case .failed(let message):
            VStack(alignment: .leading, spacing: 8) {
                Text("Can't reach openpassd").font(.headline)
                Text(message).font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
                Button("Retry") { Task { await model.start() } }
            }
        case .pairing(let code):
            PairingView(code: code)
        case .noVault:
            VStack(alignment: .leading, spacing: 8) {
                Text("No vault yet").font(.headline)
                Text("Create one in a terminal, then come back:").font(.callout)
                CommandText("openpass init")
            }
        case .locked:
            UnlockView()
        case .unlocked:
            switch model.screen {
            case .search:
                SearchView()
            case .add:
                AddEntryView()
            case .changePassword(let entry):
                ChangePasswordView(entry: entry)
            }
        }
    }
}

private struct PairingView: View {
    let code: String

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Approve this app").font(.headline)
            Text("The menu bar app needs approving once, like any new client. Run this in a terminal within 2 minutes:")
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
            CommandText("openpass client approve \(code)")
            HStack {
                ProgressView().controlSize(.small)
                Text("Waiting for approval…").font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}

/// Holds the unlock form's fields. An ObservableObject rather than @State,
/// which needs a macro plugin the Command Line Tools do not ship.
@MainActor
private final class UnlockForm: ObservableObject {
    @Published var password = ""
    @Published var error: String?
    @Published var busy = false
}

private struct UnlockView: View {
    @EnvironmentObject private var model: AppModel
    @StateObject private var form = UnlockForm()
    @FocusState private var focused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Vault locked").font(.headline)
            SecureField("Master password", text: $form.password)
                .textFieldStyle(.roundedBorder)
                .focused($focused)
                .onSubmit(unlock)
                .disabled(form.busy)
            if let error = form.error {
                Text(error).font(.caption).foregroundStyle(.red)
            }
            HStack {
                Spacer()
                Button("Unlock", action: unlock)
                    .keyboardShortcut(.defaultAction)
                    .disabled(form.password.isEmpty || form.busy)
            }
        }
        .onAppear { focused = true }
    }

    private func unlock() {
        guard !form.password.isEmpty, !form.busy else { return }
        form.busy = true
        let password = form.password
        Task {
            form.error = await model.unlock(password: password)
            form.password = ""
            form.busy = false
        }
    }
}

private struct SearchView: View {
    @EnvironmentObject private var model: AppModel
    @FocusState private var focused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                TextField("Search", text: $model.query)
                    .textFieldStyle(.roundedBorder)
                    .focused($focused)
                    .onSubmit(copySelected)
                    .onKeyPress(.downArrow) { move(1); return .handled }
                    .onKeyPress(.upArrow) { move(-1); return .handled }
                Button { model.screen = .add } label: { Image(systemName: "plus") }
                    .buttonStyle(.borderless)
                    .keyboardShortcut("n", modifiers: .command)
                    .help("Add an entry (⌘N)")
            }

            let results = model.filtered
            if results.isEmpty {
                Text(model.entries.isEmpty ? "The vault is empty." : "No matches.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, minHeight: 60)
            } else {
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(spacing: 2) {
                            ForEach(results) { entry in
                                EntryRow(entry: entry, selected: entry.id == model.selection(in: results))
                                    .id(entry.id)
                            }
                        }
                    }
                    .frame(maxHeight: 320)
                    .onChange(of: model.selectedID) { _, id in
                        if let id { proxy.scrollTo(id) }
                    }
                }
            }

            Text("↩ copies the password · ↑↓ to choose · ⌘N adds")
                .font(.caption2)
                .foregroundStyle(.tertiary)
        }
        .onAppear { focused = true }
        // Covers both the popover closing and switching to a form: a revealed
        // password must not be waiting there when you come back.
        .onDisappear { model.hidePassword() }
        .onChange(of: model.query) { model.selectedID = nil }
    }

    private func move(_ delta: Int) {
        let results = model.filtered
        guard !results.isEmpty else { return }
        let current = results.firstIndex { $0.id == model.selection(in: results) } ?? 0
        model.selectedID = results[min(max(current + delta, 0), results.count - 1)].id
    }

    private func copySelected() {
        let results = model.filtered
        guard let id = model.selection(in: results), let entry = results.first(where: { $0.id == id }) else { return }
        Task { await model.copyPassword(entry) }
    }
}

private struct EntryRow: View {
    @EnvironmentObject private var model: AppModel
    let entry: Entry
    let selected: Bool

    private var password: String? {
        model.revealed?.id == entry.id ? model.revealed?.password : nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            header
            if let password {
                RevealedDetails(username: entry.username, password: password)
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 5)
        .background(
            RoundedRectangle(cornerRadius: 6)
                .fill(selected ? Color.accentColor.opacity(0.18) : .clear)
        )
        .contentShape(Rectangle())
        // Hovering selects, so the mouse and the arrow keys share one highlight.
        .onHover { if $0 { model.selectedID = entry.id } }
        .onTapGesture { Task { await model.copyPassword(entry) } }
    }

    private var header: some View {
        HStack(spacing: 8) {
            VStack(alignment: .leading, spacing: 1) {
                Text(entry.name).lineLimit(1)
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer()
            Button { Task { await model.toggleReveal(entry) } } label: {
                Image(systemName: password == nil ? "eye" : "eye.slash")
            }
            .buttonStyle(.borderless)
            .help(password == nil ? "Show username and password" : "Hide")
            if !entry.username.isEmpty {
                Button { model.copyUsername(entry) } label: { Image(systemName: "person") }
                    .buttonStyle(.borderless)
                    .help("Copy username")
            }
            Button { Task { await model.copyPassword(entry) } } label: { Image(systemName: "key") }
                .buttonStyle(.borderless)
                .help("Copy password")
            Button { model.screen = .changePassword(entry) } label: {
                Image(systemName: "arrow.triangle.2.circlepath")
            }
            .buttonStyle(.borderless)
            .help("Change password")
        }
    }

    private var subtitle: String {
        let host = entry.urls.first.flatMap { URL(string: $0)?.host } ?? entry.urls.first
        return [entry.username, host].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " · ")
    }
}

/// The username and password under a row after its eye is clicked.
private struct RevealedDetails: View {
    let username: String
    let password: String

    var body: some View {
        Grid(alignment: .leading, horizontalSpacing: 8, verticalSpacing: 3) {
            GridRow {
                Text("Username").foregroundStyle(.secondary)
                Text(username.isEmpty ? "—" : username)
            }
            GridRow {
                Text("Password").foregroundStyle(.secondary)
                Text(password)
            }
        }
        .font(.system(.caption, design: .monospaced))
        .textSelection(.enabled)
        .padding(6)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 5).fill(Color.primary.opacity(0.06)))
    }
}

private struct Footer: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        HStack(spacing: 10) {
            Circle()
                .fill(model.watching ? Color.green : Color.orange)
                .frame(width: 7, height: 7)
                .help(model.watching
                      ? "Answering approval requests from the browser"
                      : "Not listening for approval requests")
            Text(statusText).font(.caption).foregroundStyle(.secondary)
            Spacer()
            Menu {
                Toggle("Launch at login", isOn: Binding(
                    get: { model.launchAtLogin },
                    set: { model.setLaunchAtLogin($0) }))
                Divider()
                Button("Quit openpass menu") { NSApp.terminate(nil) }
            } label: {
                Image(systemName: "gearshape")
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .fixedSize()
            if model.phase == .unlocked {
                Button("Lock") { Task { await model.lock() } }
                    .controlSize(.small)
            }
        }
    }

    private var statusText: String {
        guard model.phase == .unlocked, let status = model.status else {
            return model.watching ? "Daemon running" : ""
        }
        var parts: [String] = []
        if let count = status.entryCount { parts.append("\(count) entries") }
        if let secs = status.locksIn { parts.append("locks in \(secs / 60)m") }
        return parts.joined(separator: " · ")
    }
}

private struct CommandText: View {
    let command: String
    init(_ command: String) { self.command = command }

    var body: some View {
        HStack {
            Text(command)
                .font(.system(.callout, design: .monospaced))
                .textSelection(.enabled)
            Spacer()
            Button { Clipboard.copyPlain(command) } label: { Image(systemName: "doc.on.doc") }
                .buttonStyle(.borderless)
                .help("Copy")
        }
        .padding(6)
        .background(RoundedRectangle(cornerRadius: 5).fill(Color.primary.opacity(0.06)))
    }
}
