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

// Sentinel entry point for the SwiftUI UI layer.
// This stays tiny on purpose: create shared app state, inject into views.
import Darwin
import SwiftUI

/// Owns the per-user process lock that prevents separate app copies from
/// connecting to the same backend and driver bridge simultaneously.
final class SingleInstanceCoordinator {
    static let shared = SingleInstanceCoordinator()

    private var lockFileDescriptor: Int32 = -1
    private(set) var isPrimary = false

    private init() {}

    func acquire() -> Bool {
        if isPrimary {
            return true
        }

        if activateExistingInstance() {
            return false
        }

        let bundleIdentifier = Bundle.main.bundleIdentifier ?? "com.sentinel.SentinelForge"
        let lockURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(bundleIdentifier).instance.lock", isDirectory: false)
        let descriptor = open(lockURL.path, O_CREAT | O_RDWR, mode_t(S_IRUSR | S_IWUSR))

        guard descriptor >= 0 else {
            NSLog("[SingleInstance] Refusing launch: unable to open %@", lockURL.path)
            return false
        }

        guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
            close(descriptor)
            _ = activateExistingInstance()
            NSLog("[SingleInstance] Refusing launch: another SentinelForge instance owns the lock")
            return false
        }

        lockFileDescriptor = descriptor
        isPrimary = true
        return true
    }

    func release() {
        guard lockFileDescriptor >= 0 else { return }
        flock(lockFileDescriptor, LOCK_UN)
        close(lockFileDescriptor)
        lockFileDescriptor = -1
        isPrimary = false
    }

    @discardableResult
    private func activateExistingInstance() -> Bool {
        guard let bundleIdentifier = Bundle.main.bundleIdentifier else { return false }

        let currentProcessIdentifier = ProcessInfo.processInfo.processIdentifier
        guard let existing = NSRunningApplication
            .runningApplications(withBundleIdentifier: bundleIdentifier)
            .first(where: { $0.processIdentifier != currentProcessIdentifier })
        else {
            return false
        }

        existing.activate(options: [.activateAllWindows, .activateIgnoringOtherApps])
        return true
    }
}

/// Class AppDelegate.
class AppDelegate: NSObject, NSApplicationDelegate {
    private(set) var isPrimaryInstance = false

    func applicationWillFinishLaunching(_ notification: Notification) {
        isPrimaryInstance = SingleInstanceCoordinator.shared.acquire()
        guard isPrimaryInstance else {
            DispatchQueue.main.async {
                NSApp.terminate(nil)
            }
            return
        }
    }

    /// Function applicationDidFinishLaunching.
    func applicationDidFinishLaunching(_ notification: Notification) {
        guard isPrimaryInstance else { return }

        // Force the app to be a "regular" foreground app
        NSApp.setActivationPolicy(.regular)

        // Activate the app (bring to front) ignoring other apps
        NSApp.activate(ignoringOtherApps: true)

        // Force the main window to make itself key and order front
        if let window = NSApp.windows.first {
            window.makeKeyAndOrderFront(nil)
        }

        // Connect only after this process owns the single-instance lock.
        _ = DriverBridgeClient.shared
    }

    /// Function applicationWillTerminate.
    func applicationWillTerminate(_ notification: Notification) {
        guard isPrimaryInstance else { return }

        // Ensure backend is stopped when app quits
        BackendManager.shared.stop()
        SingleInstanceCoordinator.shared.release()
    }

    /// Function applicationShouldTerminateAfterLastWindowClosed.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return true
    }
}

@main
/// Struct SentinelApp.
struct SentinelApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    // One shared state container for chat + IPC. Keeps UI and LLM in sync.
    @StateObject private var llmService = LLMService()
    @StateObject private var appState: HelixAppState
    @StateObject private var backendManager = BackendManager.shared

    init() {
        let llm = LLMService()
        _llmService = StateObject(wrappedValue: llm)
        _appState = StateObject(wrappedValue: HelixAppState(llm: llm))
    }

    var body: some Scene {
        WindowGroup {
            MainWindowView()
                .environmentObject(appState)
                .textSelection(.enabled)
                .task {
                    guard appDelegate.isPrimaryInstance else { return }

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
