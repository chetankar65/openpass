import SwiftUI

@main
struct OpenPassMenuApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        MenuBarExtra {
            MenuView()
                .environmentObject(model)
        } label: {
            Image(systemName: model.menuBarIcon)
        }
        .menuBarExtraStyle(.window)
    }
}
