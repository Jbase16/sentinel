// Sentinel entry point for the SwiftUI UI layer.
// This stays tiny on purpose: create shared app state, inject into views.
import SwiftUI

class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        // Force the app to be a "regular" foreground app
        NSApp.setActivationPolicy(.regular)
        
        // Activate the app (bring to front) ignoring other apps
        NSApp.activate(ignoringOtherApps: true)
        
        // Force the main window to make itself key and order front
        if let window = NSApp.windows.first {
            window.makeKeyAndOrderFront(nil)
        }
    }
}

@main
struct SentinelApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    
    // One shared state container for chat + IPC. Keeps UI and LLM in sync.
    @StateObject private var appState = HelixAppState()

    var body: some Scene {
        WindowGroup {
            MainWindowView()
                .environmentObject(appState)
        }
        // Ensure standard window commands are available
        .commands {
            SidebarCommands()
            TextEditingCommands()
        }
    }
}
