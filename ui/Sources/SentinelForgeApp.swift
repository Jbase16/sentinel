// ============================================================================
// ui/Sources/SentinelForgeApp.swift
// Sentinelforgeapp Component
// ============================================================================
//
// PURPOSE:
// This Swift component is part of the SentinelForge macOS UI.
// [Specific purpose based on component name: SentinelForgeApp]
//
// KEY RESPONSIBILITIES:
// - [Automatically generated - review and enhance based on actual functionality]
//
// INTEGRATION:
// - Used by: [To be documented]
// - Depends on: [To be documented]
//
// ============================================================================

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
    
    func applicationWillTerminate(_ notification: Notification) {
        // Ensure backend is stopped when app quits
        BackendManager.shared.stop()
    }
    
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return true
    }
}

@main
struct SentinelApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    
    // One shared state container for chat + IPC. Keeps UI and LLM in sync.
    @StateObject private var appState = HelixAppState()
    @StateObject private var backendManager = BackendManager.shared

    var body: some Scene {
        WindowGroup {
            MainWindowView()
                .environmentObject(appState)
                .task {
                    // Auto-boot the Neural Core when the window opens
                    backendManager.start()
                }
        }
        .windowResizability(.contentSize)
        .defaultSize(width: 1000, height: 700)
        .commands {
            SidebarCommands()
            TextEditingCommands()
        }
    }
}
