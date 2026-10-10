import AppKit

/// Asks the human about approval requests, one at a time.
///
/// Fails closed the same way the daemon does: closing the alert, or letting it
/// run past the request's expiry, is a no.
@MainActor
final class ApprovalPresenter {
    /// Matches `openpass watch -remember`'s default.
    static let rememberSeconds = 300

    private var queue: [(ApprovalRequest, (Bool, Int) -> Void)] = []
    private var showing = false
    private var seen: Set<String> = []

    func enqueue(_ req: ApprovalRequest, answer: @escaping (_ allow: Bool, _ rememberSeconds: Int) -> Void) {
        // A reconnecting watcher is re-sent everything still pending.
        guard seen.insert(req.id).inserted else { return }
        queue.append((req, answer))
        showNext()
    }

    private func showNext() {
        guard !showing, !queue.isEmpty else { return }
        let (req, answer) = queue.removeFirst()

        guard req.expires > Date() else {
            answer(false, 0)
            showNext()
            return
        }
        showing = true

        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "\(req.client) wants a password"
        let site = req.domain.isEmpty ? "no site" : req.domain
        alert.informativeText = "Entry: \(req.entry.isEmpty ? "(unknown)" : req.entry)\nSite: \(site)"
        alert.addButton(withTitle: "Deny")
        alert.addButton(withTitle: "Allow")

        let remember = NSButton(checkboxWithTitle: "Don't ask again for this site for 5 minutes",
                                target: nil, action: nil)
        alert.accessoryView = remember

        // Dismiss when the daemon stops waiting; an answer after that is
        // rejected anyway.
        let timer = Timer(timeInterval: max(req.expires.timeIntervalSinceNow, 0), repeats: false) { _ in
            NSApp.abortModal()
        }
        RunLoop.main.add(timer, forMode: .modalPanel)

        NSApp.activate(ignoringOtherApps: true)
        alert.window.level = .floating
        let response = alert.runModal()
        timer.invalidate()

        let allow = response == .alertSecondButtonReturn
        answer(allow, allow && remember.state == .on ? Self.rememberSeconds : 0)

        showing = false
        showNext()
    }
}
