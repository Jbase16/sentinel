// ============================================================================
// ui/Sources/Services/PTYClient.swift
// Ptyclient Component
// ============================================================================
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
// ============================================================================

//
//  PTYClient.swift
//  SentinelForgeUI
//
//  Connects to the Command Deck Terminal.
//

import Foundation

class PTYClient: ObservableObject {
    private var webSocketTask: URLSessionWebSocketTask?
    
    @Published var output: String = ""
    @Published var isConnected: Bool = false
    
    func connect(url: URL) {
        let session = URLSession(configuration: .default)
        webSocketTask = session.webSocketTask(with: url)
        webSocketTask?.resume()
        self.isConnected = true
        
        receiveMessage()
    }
    
    func write(_ command: String) {
        let message = URLSessionWebSocketTask.Message.string(command)
        webSocketTask?.send(message) { error in
            if let error = error {
                print("PTY Write Error: \(error)")
            }
        }
    }
    
    func sendResize(rows: Int, cols: Int) {
        let cmd = "{\"type\":\"resize\", \"rows\":\(rows), \"cols\":\(cols)}"
        write(cmd)
    }
    
    private func receiveMessage() {
        webSocketTask?.receive { [weak self] result in
            switch result {
            case .failure(let error):
                print("PTY Read Error: \(error)")
                self?.isConnected = false
            case .success(let message):
                switch message {
                case .string(let text):
                    DispatchQueue.main.async {
                        self?.output += text
                    }
                case .data(let data):
                    if let text = String(data: data, encoding: .utf8) {
                        DispatchQueue.main.async {
                            self?.output += text
                        }
                    }
                @unknown default: break
                }
                self?.receiveMessage()
            }
        }
    }
}
