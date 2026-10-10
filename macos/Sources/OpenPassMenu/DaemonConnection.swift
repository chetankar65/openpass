import Foundation

enum OpenPassError: LocalizedError {
    case message(String)
    case rpc(code: Int, message: String)
    case disconnected

    // Wire error codes from docs/API.md.
    static let vaultLocked = -32001
    static let badPassword = -32002
    static let notPaired = -32005

    var errorDescription: String? {
        switch self {
        case .message(let m): return m
        case .rpc(_, let m): return m
        case .disconnected: return "lost the connection to openpassd"
        }
    }

    func isCode(_ code: Int) -> Bool {
        if case .rpc(let c, _) = self { return c == code }
        return false
    }
}

/// One connection to the daemon's Unix socket, speaking newline-delimited
/// JSON-RPC. The Swift counterpart of internal/client.

final class DaemonConnection: @unchecked Sendable {
    private let fd: Int32
    private let identity: Identity
    private let lock = NSLock()
    private var nextID = 0
    private var pending: [Int: CheckedContinuation<Any?, Error>] = [:]
    private var closed = false

    /// Called on the reader thread with (method, params).
    var onNotification: ((String, Any?) -> Void)?
    /// Called once, on the reader thread, when the connection drops.
    var onClose: (() -> Void)?

    private init(fd: Int32, identity: Identity) {
        self.fd = fd
        self.identity = identity
    }

    static func connect(socketPath: String, identity: Identity) throws -> DaemonConnection {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw OpenPassError.message("socket() failed: \(errno)") }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(socketPath.utf8)
        let capacity = MemoryLayout.size(ofValue: addr.sun_path)
        guard pathBytes.count < capacity else {
            Darwin.close(fd)
            throw OpenPassError.message("socket path is too long: \(socketPath)")
        }
        withUnsafeMutableBytes(of: &addr.sun_path) { buf in
            buf.copyBytes(from: pathBytes)
            buf[pathBytes.count] = 0
        }

        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard result == 0 else {
            let err = errno
            Darwin.close(fd)
            throw OpenPassError.message("could not connect to \(socketPath): \(String(cString: strerror(err)))")
        }

        // A write to a socket the daemon closed must fail, not kill the app.
        var on: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))

        let conn = DaemonConnection(fd: fd, identity: identity)
        let reader = Thread { conn.readLoop() }
        reader.name = "openpassd reader"
        reader.start()
        return conn
    }

    func close() {
        lock.lock()
        let wasClosed = closed
        closed = true
        lock.unlock()
        if !wasClosed { shutdown(fd, SHUT_RDWR) }
    }

    /// Sends one request and waits for its result. `signed` is false only for
    /// the two unauthenticated methods, hello and client.pair.
    func call(_ method: String, _ params: [String: Any]? = nil, signed: Bool = true) async throws -> Any? {
        let rawParams = try params.map { try JSONSerialization.data(withJSONObject: $0) }

        var line = Data()
        let id = lock.withLock {
            nextID += 1
            return nextID
        }

        // Built by hand so the params bytes on the wire are exactly the ones
        // that were signed.
        line += Data("{\"jsonrpc\":\"2.0\",\"id\":\(id),\"method\":".utf8)
        line += try JSONSerialization.data(withJSONObject: method, options: .fragmentsAllowed)
        if let rawParams {
            line += Data(",\"params\":".utf8) + rawParams
        }
        if signed {
            let auth = try identity.sign(method: method, params: rawParams)
            line += Data(",\"auth\":".utf8) + (try JSONSerialization.data(withJSONObject: auth))
        }
        line += Data("}\n".utf8)

        return try await withCheckedThrowingContinuation { cont in
            lock.lock()
            if closed {
                lock.unlock()
                cont.resume(throwing: OpenPassError.disconnected)
                return
            }
            pending[id] = cont
            lock.unlock()

            if !writeAll(line) {
                lock.lock()
                let waiting = pending.removeValue(forKey: id)
                lock.unlock()
                waiting?.resume(throwing: OpenPassError.disconnected)
            }
        }
    }

    private func writeAll(_ data: Data) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return data.withUnsafeBytes { buf in
            var offset = 0
            while offset < buf.count {
                let n = write(fd, buf.baseAddress! + offset, buf.count - offset)
                if n <= 0 { return false }
                offset += n
            }
            return true
        }
    }

    private func readLoop() {
        var buffer = Data()
        var chunk = [UInt8](repeating: 0, count: 64 * 1024)

        while true {
            let n = read(fd, &chunk, chunk.count)
            if n <= 0 { break }
            buffer.append(contentsOf: chunk[0..<n])

            while let newline = buffer.firstIndex(of: 0x0A) {
                let line = buffer[buffer.startIndex..<newline]
                buffer = Data(buffer[(newline + 1)...])
                handle(line: Data(line))
            }
        }

        Darwin.close(fd)
        lock.lock()
        closed = true
        let waiting = pending
        pending.removeAll()
        lock.unlock()
        for cont in waiting.values { cont.resume(throwing: OpenPassError.disconnected) }
        onClose?()
    }

    private func handle(line: Data) {
        guard let message = (try? JSONSerialization.jsonObject(with: line)) as? [String: Any] else { return }

        guard let id = message["id"] as? Int else {
            if let method = message["method"] as? String {
                onNotification?(method, message["params"])
            }
            return
        }

        lock.lock()
        let cont = pending.removeValue(forKey: id)
        lock.unlock()

        if let error = message["error"] as? [String: Any] {
            cont?.resume(throwing: OpenPassError.rpc(code: error["code"] as? Int ?? 0,
                                                     message: error["message"] as? String ?? "unknown error"))
        } else {
            cont?.resume(returning: message["result"])
        }
    }
}
