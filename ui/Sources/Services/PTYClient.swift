//
// PURPOSE:
// This Swift component is part of the SentinelForge macOS UI.
// [Specific purpose based on component name: PTYClient]
//
// KEY RESPONSIBILITIES:
// - [Automatically generated - review and enhance based on actual functionality]
//
// INTEGRATION:
// - Used by: [To be documented]
// - Depends on: [To be documented]
//

//
//  PTYClient.swift
//  SentinelForgeUI
//
//  Connects to the Command Deck Terminal.
//

import Foundation

/// Class PTYClient.
/// Delegate protocol for PTY events
protocol PTYClientDelegate: AnyObject {
    func onOutputReceived(_ text: String)
    func onConnectionStateChanged(isConnected: Bool)
}

/// Class PTYClient.
class PTYClient: ObservableObject {
    private var webSocketTask: URLSessionWebSocketTask?
    weak var delegate: PTYClientDelegate?
    @Published var isConnected: Bool = false
    private var hasConfirmedConnection: Bool = false

    /// Path to the token file
    private static let tokenPath: URL = {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".sentinelforge")
            .appendingPathComponent("api_token")
    }()

    private static func readToken() -> String? {
        try? String(contentsOf: tokenPath, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Function connect.
    func connect(url: URL) {
        let config = URLSessionConfiguration.default
        let session = URLSession(
            configuration: config, delegate: nil, delegateQueue: OperationQueue.main)

        var request = URLRequest(url: url)
        if let token = Self.readToken() {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        print("[PTYClient] Connecting to \(url) (Auth: \(Self.readToken() != nil))...")
        webSocketTask = session.webSocketTask(with: request)
        webSocketTask?.resume()

        // Removed optimistic connection state - wait for first message
        self.hasConfirmedConnection = false

        receiveMessage()
    }

    /// Function write.
    func write(_ data: String) {
        // Wrap input in JSON protocol
        // {"type": "input", "data": "ls\n"}
        let payload: [String: Any] = ["type": "input", "data": data]
        if let jsonData = try? JSONSerialization.data(withJSONObject: payload),
            let jsonString = String(data: jsonData, encoding: .utf8)
        {

            let message = URLSessionWebSocketTask.Message.string(jsonString)
            webSocketTask?.send(message) { error in
                if let error = error {
                    print("PTY Write Error: \(error)")
                }
            }
        }
    }

    /// Function sendResize.
    func sendResize(rows: Int, cols: Int) {
        let cmd = "{\"type\":\"resize\", \"rows\":\(rows), \"cols\":\(cols)}"
        let message = URLSessionWebSocketTask.Message.string(cmd)
        webSocketTask?.send(message) { error in
            if let error = error { print("PTY Resize Error: \(error)") }
        }
    }

    private func receiveMessage() {
        webSocketTask?.receive { [weak self] result in
            guard let self = self else { return }

            switch result {
            case .failure(let error):
                print("PTY Read Error: \(error)")
                DispatchQueue.main.async {
                    self.isConnected = false
                    self.delegate?.onConnectionStateChanged(isConnected: false)
                }

            case .success(let message):
                // Confirm connection on first successful receive
                if !self.hasConfirmedConnection {
                    DispatchQueue.main.async {
                        self.hasConfirmedConnection = true
                        self.isConnected = true
                        self.delegate?.onConnectionStateChanged(isConnected: true)
                    }
                }

                switch message {
                case .string(let text):
                    self.handleIncomingText(text)

                case .data(let data):
                    if let text = String(data: data, encoding: .utf8) {
                        self.handleIncomingText(text)
                    }
                @unknown default: break
                }
                self.receiveMessage()
            }
        }
    }

    private func handleIncomingText(_ text: String) {
        // Try to parse structured JSON output first
        if let data = text.data(using: .utf8),
            let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let type = json["type"] as? String,
            type == "output",
            let payload = json["data"] as? String
        {

            DispatchQueue.main.async {
                self.delegate?.onOutputReceived(payload)
            }
            return
        }

        // Fallback: Raw text
        DispatchQueue.main.async {
            self.delegate?.onOutputReceived(text)
        }
    }

    func disconnect() {
        webSocketTask?.cancel(with: .normalClosure, reason: nil)
        isConnected = false
    }
}
