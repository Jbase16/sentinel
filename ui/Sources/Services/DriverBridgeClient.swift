import Foundation
import Combine
import AppKit

func logToSnd(_ message: String) {
    print(message)
    if let data = (message + "\n").data(using: .utf8) {
        let url = URL(fileURLWithPath: "/tmp/snd_swift.log")
        if let handle = try? FileHandle(forWritingTo: url) {
            handle.seekToEndOfFile()
            handle.write(data)
            handle.closeFile()
        } else {
            try? data.write(to: url)
        }
    }
}

public class DriverBridgeClient: NSObject, ObservableObject, URLSessionWebSocketDelegate {
    public static let shared = DriverBridgeClient()
    
    private var webSocketTask: URLSessionWebSocketTask?
    private lazy var session: URLSession = {
        let configuration = URLSessionConfiguration.default
        return URLSession(configuration: configuration, delegate: self, delegateQueue: OperationQueue.main)
    }()
    private var isConnected = false
    
    // Command dispatch handling
    private var commandTask: Task<Void, Never>?
    
    // Open Ghost browser window
    private var currentBrowserWindowController: NSWindowController?
    
    private override init() {
        super.init()
        connect()
    }
    
    public func connect() {
        guard !isConnected else { return }
        logToSnd("[SND] connect() called")
        
        let url = URL(string: "ws://127.0.0.1:8765/v1/driver/bridge")!
        webSocketTask = session.webSocketTask(with: url)
        webSocketTask?.resume()
        
        isConnected = true
        receiveMessage()
        logToSnd("[SND] WebSocket task resumed")
    }
    
    public func disconnect() {
        webSocketTask?.cancel(with: .goingAway, reason: nil)
        isConnected = false
        logToSnd("[SND] disconnect() called")
    }
    
    public func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask, didOpenWithProtocol protocol: String?) {
        logToSnd("[SND] WebSocket didOpenWithProtocol")
    }
    
    public func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask, didCloseWith closeCode: URLSessionWebSocketTask.CloseCode, reason: Data?) {
        logToSnd("[SND] WebSocket didCloseWith code: \(closeCode.rawValue)")
    }
    
    private func receiveMessage() {
        webSocketTask?.receive { [weak self] result in
            guard let self = self else { return }
            
            switch result {
            case .failure(let error):
                logToSnd("[SND] WebSocket receive error: \(error)")
                BackendManager.shared.appendLogLine("[SND] WebSocket receive error: \(error)")
                self.isConnected = false
                DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) {
                    self.connect()
                }
            case .success(let message):
                logToSnd("[SND] WebSocket received message")
                switch message {
                case .string(let text):
                    self.handleCommand(text)
                case .data(_):
                    break
                @unknown default:
                    break
                }
                self.receiveMessage()
            }
        }
    }
    
    private func handleCommand(_ jsonString: String) {
        guard let data = jsonString.data(using: .utf8),
              let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let command = dict["command"] as? String,
              let reqId = dict["request_id"] as? String else {
            return
        }
        
        let args = dict["args"] as? [String: Any] ?? [:]
        logToSnd("[SND] Handling command: \(command)")
        
        Task { @MainActor in
            do {
                var result: Any? = nil
                
                switch command {
                case "launch":
                    result = try await launchBrowser(args: args)
                case "navigate":
                    if let url = args["url"] as? String {
                        result = try await navigate(url: url)
                    }
                case "click":
                    if let selector = args["selector"] as? [String: String] {
                        result = try await click(selector: selector)
                    }
                case "fill":
                    if let selector = args["selector"] as? [String: String],
                       let value = args["value"] as? String {
                        result = try await fill(selector: selector, value: value)
                    }
                case "wait_for":
                    if let selector = args["selector"] as? [String: String],
                       let timeoutS = args["timeout_s"] as? Double {
                        result = try await waitFor(selector: selector, timeoutS: timeoutS)
                    }
                case "extract":
                    if let selector = args["selector"] as? [String: String],
                       let mode = args["mode"] as? String {
                        result = try await extract(selector: selector, mode: mode)
                    }
                case "screenshot":
                    result = try await screenshot()
                case "current_url":
                    result = try await currentUrl()
                case "start_recording":
                    result = try await startRecording()
                case "start_network_capture":
                    result = try await startNetworkCapture()
                case "wait_for_close":
                    result = try await waitForClose()
                case "close":
                    result = try await closeBrowser()
                case "get_cookies":
                    result = try await getCookies()
                default:
                    throw NSError(domain: "SND", code: 400, userInfo: [NSLocalizedDescriptionKey: "Unknown command \(command)"])
                }
                
                self.sendResponse(reqId: reqId, result: result)
            } catch {
                self.sendError(reqId: reqId, error: error.localizedDescription)
            }
        }
    }
    
    private func sendResponse(reqId: String, result: Any?) {
        var dict: [String: Any] = ["request_id": reqId]
        if let res = result { dict["result"] = res }
        send(dict)
    }
    
    private func sendError(reqId: String, error: String) {
        send(["request_id": reqId, "error": error])
    }
    
    public func sendSpontaneousEvent(event: String, payload: [String: Any]) {
        var dict = payload
        dict["event"] = event
        send(dict)
    }
    
    private func send(_ dict: [String: Any]) {
        guard let data = try? JSONSerialization.data(withJSONObject: dict),
              let string = String(data: data, encoding: .utf8) else { return }
        
        webSocketTask?.send(.string(string)) { error in
            if let e = error {
                logToSnd("[SND] Send error: \(e)")
                BackendManager.shared.appendLogLine("[SND] Send error: \(e)")
            }
        }
    }
    
    // MARK: - Browser Operations
    
    @MainActor
    private func launchBrowser(args: [String: Any]) async throws -> String {
        if currentBrowserWindowController != nil {
            try await closeBrowser()
        }
        
        let window = GhostBrowserWindow(
            contentRect: NSRect(x: 100, y: 100, width: 1024, height: 768),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        let wc = NSWindowController(window: window)
        wc.showWindow(nil)
        window.makeKeyAndOrderFront(nil)
        
        self.currentBrowserWindowController = wc
        return "ok"
    }
    
    @MainActor
    private func getBrowser() throws -> GhostBrowserWindow {
        guard let wc = currentBrowserWindowController,
              let window = wc.window as? GhostBrowserWindow else {
            throw NSError(domain: "SND", code: 404, userInfo: [NSLocalizedDescriptionKey: "No active browser session"])
        }
        return window
    }
    
    @MainActor private func navigate(url: String) async throws -> String {
        let b = try getBrowser()
        try await b.navigate(url: url)
        return "ok"
    }
    
    @MainActor private func click(selector: [String: String]) async throws -> String {
        let b = try getBrowser()
        try await b.click(selector: selector)
        return "ok"
    }
    
    @MainActor private func fill(selector: [String: String], value: String) async throws -> String {
        let b = try getBrowser()
        try await b.fill(selector: selector, value: value)
        return "ok"
    }
    
    @MainActor private func waitFor(selector: [String: String], timeoutS: Double) async throws -> String {
        let b = try getBrowser()
        try await b.waitFor(selector: selector, timeoutS: timeoutS)
        return "ok"
    }
    
    @MainActor private func extract(selector: [String: String], mode: String) async throws -> String {
        let b = try getBrowser()
        return try await b.extract(selector: selector, mode: mode)
    }
    
    @MainActor private func screenshot() async throws -> String {
        let b = try getBrowser()
        return try await b.screenshotBase64()
    }
    
    @MainActor private func currentUrl() async throws -> String {
        let b = try getBrowser()
        return try await b.currentUrl()
    }
    
    @MainActor private func startRecording() async throws -> String {
        let b = try getBrowser()
        try await b.startRecording()
        return "ok"
    }
    
    @MainActor private func startNetworkCapture() async throws -> String {
        let b = try getBrowser()
        try await b.startNetworkCapture()
        return "ok"
    }
    
    @MainActor private func waitForClose() async throws -> String {
        let b = try getBrowser()
        return try await withCheckedThrowingContinuation { continuation in
            b.onClose = {
                continuation.resume(returning: "closed")
            }
        }
    }
    
    @MainActor private func closeBrowser() async throws -> String {
        if let wc = currentBrowserWindowController {
            if let b = wc.window as? GhostBrowserWindow {
                b.onClose?()
            }
            wc.close()
            currentBrowserWindowController = nil
        }
        return "ok"
    }
    
    @MainActor private func getCookies() async throws -> [String: String] {
        let b = try getBrowser()
        return try await b.getCookies()
    }
}
