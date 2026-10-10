import AppKit

/// Puts secrets on the pasteboard and takes them off again.
@MainActor
enum Clipboard {
    static let clearAfter: TimeInterval = 30

    // nspasteboard.org markers: clipboard managers and Universal Clipboard
    // skip items carrying these, so the password is not kept in a history.
    private static let concealed = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
    private static let transient = NSPasteboard.PasteboardType("org.nspasteboard.TransientType")

    static func copySecret(_ secret: String) {
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(secret, forType: .string)
        pb.setData(Data(), forType: concealed)
        pb.setData(Data(), forType: transient)
        let ours = pb.changeCount

        DispatchQueue.main.asyncAfter(deadline: .now() + clearAfter) {
            // Only clear if nothing else has been copied since.
            if NSPasteboard.general.changeCount == ours {
                NSPasteboard.general.clearContents()
            }
        }
    }

    static func copyPlain(_ text: String) {
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(text, forType: .string)
    }
}
