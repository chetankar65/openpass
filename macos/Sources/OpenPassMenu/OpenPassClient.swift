import Foundation

/// Must match client.ProtocolVersion.
let protocolVersion = 1

struct Paths {
    let base: URL
    var socket: String { base.appendingPathComponent("run/openpassd.sock").path }
    var vault: String { base.appendingPathComponent("vault.opv").path }
    var identity: URL { base.appendingPathComponent("menubar.key") }

    static let `default` = Paths(base: FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".openpass"))
}

struct Status {
    let vaultPresent: Bool
    let locked: Bool
    let entryCount: Int?
    let locksIn: Int?
}

struct Entry: Identifiable, Hashable {
    let id: String
    let name: String
    let username: String
    let urls: [String]
    let tags: [String]

    init(_ raw: [String: Any]) {
        id = raw["id"] as? String ?? ""
        name = raw["name"] as? String ?? ""
        username = raw["username"] as? String ?? ""
        urls = raw["urls"] as? [String] ?? []
        tags = raw["tags"] as? [String] ?? []
    }

    /// Case-insensitive substring match on what a person would type, the same
    /// fields the CLI's resolver searches.
    func matches(_ query: String) -> Bool {
        if query.isEmpty { return true }
        let q = query.lowercased()
        return name.lowercased().contains(q)
            || username.lowercased().contains(q)
            || urls.contains { $0.lowercased().contains(q) }
            || tags.contains { $0.lowercased().contains(q) }
    }
}

struct ApprovalRequest {
    let id: String
    let client: String
    let entry: String
    let domain: String
    let expires: Date

    init?(_ raw: Any?) {
        guard let raw = raw as? [String: Any], let id = raw["id"] as? String else { return nil }
        self.id = id
        client = raw["client"] as? String ?? "A client"
        entry = raw["entry"] as? String ?? ""
        domain = raw["domain"] as? String ?? ""
        expires = Date(timeIntervalSince1970: TimeInterval(raw["expires"] as? Int ?? 0))
    }
}

enum PairState {
    case approved
    case pending(code: String)
}

/// Typed calls over a DaemonConnection. Mirrors internal/client/api.go.
struct OpenPassClient {
    let conn: DaemonConnection
    let identity: Identity

    /// Connects, starting openpassd if it is not running, and checks the
    /// protocol version before anything else.
    static func connect(paths: Paths, identity: Identity) async throws -> OpenPassClient {
        let conn = try await dialOrSpawn(paths: paths, identity: identity)
        let client = OpenPassClient(conn: conn, identity: identity)
        do {
            try await client.handshake()
        } catch {
            conn.close()
            throw error
        }
        return client
    }

    private static func dialOrSpawn(paths: Paths, identity: Identity) async throws -> DaemonConnection {
        if let conn = try? DaemonConnection.connect(socketPath: paths.socket, identity: identity) {
            return conn
        }
        try DaemonLauncher.spawn(paths: paths)

        let deadline = Date().addingTimeInterval(5)
        while Date() < deadline {
            if let conn = try? DaemonConnection.connect(socketPath: paths.socket, identity: identity) {
                return conn
            }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        throw OpenPassError.message("started openpassd but could not connect to \(paths.socket)")
    }

    func close() { conn.close() }

    func handshake() async throws {
        let result: Any?
        do {
            result = try await conn.call("hello", signed: false)
        } catch let error as OpenPassError where error.isCode(-32601) {
            throw OpenPassError.message("The running openpassd is too old for this app. Quit it with `pkill openpassd` and try again.")
        }
        let daemonProtocol = (result as? [String: Any])?["protocol"] as? Int ?? 0
        if daemonProtocol < protocolVersion {
            throw OpenPassError.message("The running openpassd is older than this app (protocol \(daemonProtocol)). Quit it with `pkill openpassd` and try again.")
        }
        if daemonProtocol > protocolVersion {
            throw OpenPassError.message("This app is older than the running openpassd (protocol \(daemonProtocol)). Rebuild it.")
        }
    }

    /// Registers this app's identity. Idempotent: an approved client gets
    /// "approved" back, a pending one gets its existing code.
    func pair() async throws -> PairState {
        let result = try await conn.call("client.pair", [
            "name": identity.name,
            "kind": identity.kind,
            "pubkey": identity.publicKey.base64EncodedString(),
        ], signed: false) as? [String: Any]

        if result?["state"] as? String == "approved" { return .approved }
        return .pending(code: result?["code"] as? String ?? "")
    }

    func status() async throws -> Status {
        let r = try await conn.call("status") as? [String: Any] ?? [:]
        return Status(vaultPresent: r["vault_present"] as? Bool ?? false,
                      locked: r["locked"] as? Bool ?? true,
                      entryCount: r["entry_count"] as? Int,
                      locksIn: r["locks_in"] as? Int)
    }

    func unlock(password: String) async throws {
        _ = try await conn.call("unlock", ["password": password])
    }

    func lock() async throws {
        _ = try await conn.call("lock")
    }

    func list() async throws -> [Entry] {
        let r = try await conn.call("vault.list") as? [String: Any]
        let raw = r?["entries"] as? [[String: Any]] ?? []
        return raw.map(Entry.init)
    }

    /// Fetches one entry's password. This is the call the daemon treats as the
    /// policy checkpoint.
    func password(id: String) async throws -> String {
        let r = try await conn.call("vault.get", ["id": id, "reveal": true]) as? [String: Any]
        guard let entry = r?["entry"] as? [String: Any], let password = entry["password"] as? String else {
            throw OpenPassError.message("the daemon returned no password")
        }
        return password
    }

    func subscribe() async throws {
        _ = try await conn.call("events.subscribe")
    }

    func respond(id: String, allow: Bool, ttlSeconds: Int) async throws {
        _ = try await conn.call("client.respond", ["id": id, "allow": allow, "ttl_seconds": ttlSeconds])
    }
}

/// Finds and starts openpassd.
enum DaemonLauncher {
    /// Next to this app's executable first (build.sh puts it there), then the
    /// places a Go install or package manager would.
    static func findDaemon() -> String? {
        var candidates: [String] = []
        if let dir = Bundle.main.executableURL?.deletingLastPathComponent() {
            candidates.append(dir.appendingPathComponent("openpassd").path)
        }
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        candidates += ["/opt/homebrew/bin/openpassd", "/usr/local/bin/openpassd", "\(home)/go/bin/openpassd"]
        return candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    static func spawn(paths: Paths) throws {
        guard let bin = findDaemon() else {
            throw OpenPassError.message("Could not find openpassd. Rebuild the app with macos/build.sh, which bundles it.")
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: bin)
        process.arguments = ["-socket", paths.socket, "-vault", paths.vault]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        // Not waited on: the daemon is meant to outlive this app, so the next
        // CLI call does not have to unlock again.
        try process.run()
    }
}
