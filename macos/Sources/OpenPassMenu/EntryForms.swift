import SwiftUI

/// Fields for both forms. An ObservableObject rather than @State, which needs a
/// macro plugin the Command Line Tools do not ship.
@MainActor
final class EntryForm: ObservableObject {
    @Published var name = ""
    @Published var username = ""
    @Published var url = ""
    @Published var notes = ""
    @Published var password = "" {
        // Typing over a generated password makes it the user's own again.
        didSet { if password != generatedValue { generatedValue = nil } }
    }
    @Published var revealed = false
    @Published var error: String?
    @Published var busy = false

    private var generatedValue: String?
    var generated: Bool { generatedValue != nil && generatedValue == password }

    func generate() {
        let value = PasswordGenerator.generate()
        generatedValue = value
        password = value
        revealed = true
    }
}

struct AddEntryView: View {
    @EnvironmentObject private var model: AppModel
    @StateObject private var form = EntryForm()
    @FocusState private var nameFocused: Bool

    private var canSave: Bool {
        !form.name.trimmingCharacters(in: .whitespaces).isEmpty && !form.password.isEmpty && !form.busy
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            FormHeader(title: "New entry")

            LabeledField("Name") {
                TextField("GitHub", text: $form.name)
                    .textFieldStyle(.roundedBorder)
                    .focused($nameFocused)
            }
            if model.nameTaken(form.name) {
                Text("An entry with this name already exists; `openpass get` will need its id.")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            LabeledField("Username") {
                TextField("Optional", text: $form.username)
                    .textFieldStyle(.roundedBorder)
            }
            LabeledField("Password") {
                PasswordInput(form: form, placeholder: "Type or generate")
            }
            LabeledField("Website") {
                TextField("github.com — used to match login pages", text: $form.url)
                    .textFieldStyle(.roundedBorder)
            }
            LabeledField("Notes") {
                TextField("Optional", text: $form.notes, axis: .vertical)
                    .lineLimit(1...4)
                    .textFieldStyle(.roundedBorder)
            }

            FormFooter(form: form, saveTitle: "Add", canSave: canSave, save: save)
        }
        .onAppear { nameFocused = true }
    }

    private func save() {
        guard canSave else { return }
        form.busy = true
        Task {
            form.error = await model.add(
                name: form.name.trimmingCharacters(in: .whitespaces),
                username: form.username.trimmingCharacters(in: .whitespaces),
                password: form.password,
                url: form.url.trimmingCharacters(in: .whitespaces),
                notes: form.notes,
                generated: form.generated)
            form.busy = false
        }
    }
}

struct ChangePasswordView: View {
    @EnvironmentObject private var model: AppModel
    @StateObject private var form = EntryForm()
    let entry: Entry

    private var canSave: Bool { !form.password.isEmpty && !form.busy }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            FormHeader(title: "Change password")

            VStack(alignment: .leading, spacing: 1) {
                Text(entry.name).font(.headline)
                if !entry.username.isEmpty {
                    Text(entry.username).font(.caption).foregroundStyle(.secondary)
                }
            }

            LabeledField("New password") {
                PasswordInput(form: form, placeholder: "Type or generate", focusOnAppear: true)
            }

            // Saving overwrites the old value, so the order matters if the
            // site rejects the new one.
            Text("Tip: copy the new password and set it on the site first, then save here.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            FormFooter(form: form, saveTitle: "Save", canSave: canSave, save: save)
        }
    }

    private func save() {
        guard canSave else { return }
        form.busy = true
        Task {
            form.error = await model.changePassword(entry, to: form.password, generated: form.generated)
            form.busy = false
        }
    }
}

private struct FormHeader: View {
    @EnvironmentObject private var model: AppModel
    let title: String

    var body: some View {
        HStack(spacing: 6) {
            Button { model.screen = .search } label: { Image(systemName: "chevron.left") }
                .buttonStyle(.borderless)
                .help("Back")
            Text(title).font(.headline)
        }
    }
}

private struct FormFooter: View {
    @EnvironmentObject private var model: AppModel
    @ObservedObject var form: EntryForm
    let saveTitle: String
    let canSave: Bool
    let save: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if let error = form.error {
                Text(error).font(.caption).foregroundStyle(.red)
            }
            HStack {
                if form.busy { ProgressView().controlSize(.small) }
                Spacer()
                Button("Cancel") { model.screen = .search }
                    .keyboardShortcut(.cancelAction)
                Button(saveTitle, action: save)
                    .keyboardShortcut(.defaultAction)
                    .disabled(!canSave)
            }
        }
    }
}

private struct LabeledField<Content: View>: View {
    let label: String
    let content: Content

    init(_ label: String, @ViewBuilder content: () -> Content) {
        self.label = label
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            content
        }
    }
}

/// A password field with show/hide, generate and copy.
private struct PasswordInput: View {
    @ObservedObject var form: EntryForm
    let placeholder: String
    var focusOnAppear = false
    @FocusState private var focused: Bool

    var body: some View {
        HStack(spacing: 6) {
            Group {
                if form.revealed {
                    TextField(placeholder, text: $form.password)
                        .font(.system(.body, design: .monospaced))
                } else {
                    SecureField(placeholder, text: $form.password)
                }
            }
            .textFieldStyle(.roundedBorder)
            .focused($focused)

            Button { form.revealed.toggle() } label: {
                Image(systemName: form.revealed ? "eye.slash" : "eye")
            }
            .buttonStyle(.borderless)
            .help(form.revealed ? "Hide" : "Show")

            Button { form.generate() } label: { Image(systemName: "dice") }
                .buttonStyle(.borderless)
                .help("Generate a \(PasswordGenerator.defaultLength)-character password")

            Button { Clipboard.copySecret(form.password) } label: { Image(systemName: "doc.on.doc") }
                .buttonStyle(.borderless)
                .disabled(form.password.isEmpty)
                .help("Copy")
        }
        .onAppear { if focusOnAppear { focused = true } }
    }
}
