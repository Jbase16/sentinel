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
    
    // Registry of authenticated persona windows for BOLA testing
    public var personaWindows: [String: GhostBrowserWindow] = [:]
    
    private override init() {
        super.init()
        connect()
    }

    private static func readAPIToken() -> String? {
        let path = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".sentinelforge", isDirectory: true)
            .appendingPathComponent("api_token")
        return try? String(contentsOf: path, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }
    
    public func connect() {
        guard !isConnected else { return }
        logToSnd("[SND] connect() called")
        
        let url = URL(string: "ws://127.0.0.1:8765/v1/driver/bridge")!
        var request = URLRequest(url: url)
        if let token = Self.readAPIToken(), !token.isEmpty {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        webSocketTask = session.webSocketTask(with: request)
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
                        result = try await navigate(
                            url: url,
                            personaId: args["persona"] as? String
                        )
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
                    guard let captureSessionId = args["capture_session"] as? String,
                          !captureSessionId.isEmpty else {
                        throw NSError(
                            domain: "SND",
                            code: 400,
                            userInfo: [
                                NSLocalizedDescriptionKey:
                                    "capture_session is required"
                            ]
                        )
                    }
                    result = try startNetworkCapture(
                        personaId: args["persona"] as? String,
                        captureSessionId: captureSessionId
                    )
                case "stop_network_capture":
                    result = try await stopNetworkCapture(personaId: args["persona"] as? String)
                case "validate_persona_windows":
                    guard let personaIds = args["personas"] as? [String] else {
                        throw NSError(
                            domain: "SND",
                            code: 400,
                            userInfo: [
                                NSLocalizedDescriptionKey:
                                    "personas must be an array of persona identifiers"
                            ]
                        )
                    }
                    result = try validatePersonaWindows(personaIds: personaIds)
                case "script_resource_urls":
                    result = try await scriptResourceURLs(
                        personaId: args["persona"] as? String
                    )
                case "wait_for_close":
                    result = try await waitForClose()
                case "close":
                    result = try await closeBrowser()
                case "get_cookies":
                    result = try await getCookies()
                case "replay":
                    await executeReplay(reqId: reqId, args: args)
                    // executeReplay handles sending its own response/error, so we return early
                    return
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
    private func getBrowser(personaId: String? = nil) throws -> GhostBrowserWindow {
        if let personaId {
            guard let personaWindow = personaWindows[personaId] else {
                throw NSError(
                    domain: "SND",
                    code: 404,
                    userInfo: [
                        NSLocalizedDescriptionKey:
                            "No authenticated window for persona '\(personaId)'"
                    ]
                )
            }
            return personaWindow
        }
        guard let wc = currentBrowserWindowController,
              let window = wc.window as? GhostBrowserWindow else {
            throw NSError(domain: "SND", code: 404, userInfo: [NSLocalizedDescriptionKey: "No active browser session"])
        }
        return window
    }
    
    @MainActor private func navigate(url: String, personaId: String? = nil) async throws -> String {
        let b = try getBrowser(personaId: personaId)
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
    
    @MainActor
    private func startNetworkCapture(
        personaId: String? = nil,
        captureSessionId: String
    ) throws -> String {
        let b = try getBrowser(personaId: personaId)
        try b.startNetworkCapture(
            personaId: personaId,
            captureSessionId: captureSessionId
        )
        return "ok"
    }

    @MainActor private func stopNetworkCapture(personaId: String? = nil) async throws -> String {
        let b = try getBrowser(personaId: personaId)
        try await b.stopNetworkCapture()
        return "ok"
    }

    @MainActor
    private func validatePersonaWindows(personaIds: [String]) throws -> String {
        guard !personaIds.isEmpty,
              Set(personaIds).count == personaIds.count,
              personaIds.allSatisfy({ !$0.isEmpty }) else {
            throw NSError(
                domain: "SND",
                code: 400,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "persona windows must contain distinct identifiers"
                ]
            )
        }
        let missing = personaIds.filter { personaWindows[$0] == nil }
        guard missing.isEmpty else {
            throw NSError(
                domain: "SND",
                code: 404,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "No registered window for persona '\(missing.joined(separator: ", "))'"
                ]
            )
        }
        return "ok"
    }

    @MainActor
    private func scriptResourceURLs(personaId: String?) async throws -> [String] {
        let b = try getBrowser(personaId: personaId)
        return try await b.scriptResourceURLs()
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
    
    @MainActor
    private func executeReplay(reqId: String, args: [String: Any]) async {
        guard let persona = args["persona"] as? String,
              let window = personaWindows[persona] else {
            sendError(reqId: reqId, error: "no authenticated window for persona '\(args["persona"] ?? "?")'")
            return
        }
        
        let params: [String: Any] = [
            "url":     args["url"]     as? String ?? "",
            "method":  args["method"]  as? String ?? "POST",
            "headers": args["headers"] as? [String: String] ?? [:],
            "body":    args["body"]    as? String as Any,
            "maxResponseChars": args["max_response_chars"] as? Int as Any,
        ]
        
        let js = """
        const p = args;
        const resp = await fetch(p.url, {
            method: p.method, headers: p.headers,
            body: (p.method === 'GET' || p.method === 'HEAD') ? undefined : p.body,
            credentials: 'include'
        });
        const cap = Number.isInteger(p.maxResponseChars) && p.maxResponseChars > 0
            ? p.maxResponseChars : 2097152;
        async function readBounded(response, limit) {
            if (!response.body || typeof response.body.getReader !== 'function') {
                const raw = await response.text();
                return {text: raw.slice(0, limit), truncated: raw.length > limit};
            }
            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            let text = '';
            let truncated = false;
            while (true) {
                const part = await reader.read();
                if (part.done) break;
                const decoded = decoder.decode(part.value, {stream: true});
                const remaining = limit - text.length;
                if (decoded.length > remaining) {
                    text += decoded.slice(0, Math.max(0, remaining));
                    truncated = true;
                    await reader.cancel();
                    break;
                }
                text += decoded;
            }
            if (!truncated) {
                const tail = decoder.decode();
                const remaining = limit - text.length;
                text += tail.slice(0, Math.max(0, remaining));
                truncated = tail.length > remaining;
            }
            return {text: text, truncated: truncated};
        }
        const captured = await readBounded(resp, cap);
        const h = {}; resp.headers.forEach((v, k) => h[k] = v);
        return {
            status: resp.status,
            headers: h,
            body: captured.text,
            body_truncated: captured.truncated
        };
        """
        
        do {
            let result = try await window.callAsyncJavaScript(js, arguments: ["args": params], in: .page)
            sendResponse(reqId: reqId, result: (result as? [String: Any]) ?? [:])
        } catch {
            sendError(reqId: reqId, error: "\(error)")
        }
    }
}
