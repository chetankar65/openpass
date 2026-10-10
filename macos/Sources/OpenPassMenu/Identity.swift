import CryptoKit
import Foundation

/// The app's keypair, stored in the same format as the Go client's
/// identityFile so either side can read it.
struct Identity {
    let id: String
    let name: String
    let kind: String
    private let key: Curve25519.Signing.PrivateKey

    var publicKey: Data { key.publicKey.rawRepresentation }

    private struct File: Codable {
        let id: String
        let name: String
        let kind: String
        // Go's ed25519.PrivateKey: the 32-byte seed followed by the public key.
        let private_key: Data
    }

    static func loadOrCreate(at url: URL, name: String, kind: String) throws -> Identity {
        if let raw = try? Data(contentsOf: url) {
            let file = try JSONDecoder().decode(File.self, from: raw)
            guard file.private_key.count == 64 else {
                throw OpenPassError.message("\(url.path) holds a malformed key")
            }
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: file.private_key.prefix(32))
            return Identity(id: file.id, name: file.name, kind: file.kind, key: key)
        }

        let key = Curve25519.Signing.PrivateKey()
        let identity = Identity(id: deriveClientID(kind: kind, publicKey: key.publicKey.rawRepresentation),
                                name: name, kind: kind, key: key)

        let file = File(id: identity.id, name: name, kind: kind,
                        private_key: key.rawRepresentation + key.publicKey.rawRepresentation)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(),
                                                withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        try JSONEncoder().encode(file).write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        return identity
    }

    /// Mirrors client.DeriveClientID.
    static func deriveClientID(kind: String, publicKey: Data) -> String {
        let sum = SHA256.hash(data: publicKey)
        return kind + "-" + sum.prefix(6).map { String(format: "%02x", $0) }.joined()
    }

    /// Builds the auth block for one request, signing the exact params bytes
    /// that go on the wire (mirrors client.SigningString).
    func sign(method: String, params: Data?) throws -> [String: Any] {
        var nonceBytes = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, nonceBytes.count, &nonceBytes) == errSecSuccess else {
            throw OpenPassError.message("could not generate a nonce")
        }
        let nonce = Data(nonceBytes).base64EncodedString()
        let ts = Int64(Date().timeIntervalSince1970)

        var message = Data((method + "\n").utf8)
        message += params ?? Data()
        message += Data(("\n" + nonce + "\n" + String(ts)).utf8)

        let sig = try key.signature(for: message)
        return ["client_id": id, "nonce": nonce, "ts": ts, "sig": sig.base64EncodedString()]
    }
}
