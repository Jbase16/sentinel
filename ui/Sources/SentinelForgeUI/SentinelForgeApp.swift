// Sentinel entry point for the SwiftUI UI layer.
// This stays tiny on purpose: create shared app state, inject into views.
import SwiftUI

@main
struct SentinelApp: App {
    // One shared state container for chat + IPC. Keeps UI and LLM in sync.
    @StateObject private var appState = HelixAppState()

    var body: some Scene {
        WindowGroup {
            MainWindowView()
                .environmentObject(appState)
        }
    }
}
