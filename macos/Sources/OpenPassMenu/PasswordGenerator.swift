/// Mirrors `openpass add -gen`: the same alphabet, which leaves out characters
/// that are easy to misread (l, o, I, O, 0, 1).
enum PasswordGenerator {
    static let alphabet = Array("abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*-_=+")
    static let defaultLength = 24

    static func generate(length: Int = defaultLength) -> String {
        // SystemRandomNumberGenerator is the OS CSPRNG, and randomElement picks
        // uniformly, so there is no modulo bias.
        var rng = SystemRandomNumberGenerator()
        return String((0..<length).map { _ in alphabet.randomElement(using: &rng)! })
    }
}
