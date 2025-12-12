//
//  CortexStream.swift
//  SentinelForgeUI
//
//  Connects to the Neural Core via WebSocket.
//  Feeds the Metal Renderer.
//

import Foundation

class CortexStream: ObservableObject {
    private var webSocketTask: URLSessionWebSocketTask?
    private var session: URLSession?
    
    @Published var nodes: [NodeModel] = []
    @Published var isConnected: Bool = false
    
    struct NodeModel: Decodable, Identifiable {
        let id: String
        let type: String
        let x: Float? // Optional, might be computed on client
        let y: Float?
    }
    
    struct GraphData: Decodable {
        let nodes: [NodeModel]
        let edges: [[String: String]] // simplified
    }

    func connect(url: URL) {
        let config = URLSessionConfiguration.default
        let session = URLSession(configuration: config, delegate: nil, delegateQueue: OperationQueue.main)
        self.session = session
        
        webSocketTask = session.webSocketTask(with: url)
        webSocketTask?.resume()
        self.isConnected = true
        
        receiveMessage()
    }
    
    private func receiveMessage() {
        webSocketTask?.receive { [weak self] result in
            guard let self = self else { return }
            
            switch result {
            case .failure(let error):
                print("WS Error: \(error)")
                DispatchQueue.main.async {
                    self.isConnected = false
                }
            case .success(let message):
                switch message {
                case .string(let text):
                    self.handleJSON(text)
                case .data(let data):
                    self.handleData(data)
                @unknown default: break
                }
                self.receiveMessage() // Loop
            }
        }
    }
    
    private func handleJSON(_ text: String) {
        guard let data = text.data(using: .utf8) else { return }
        handleData(data)
    }
    
    private func handleData(_ data: Data) {
        // Decode logic
        // For prototype, just print size
        // print("Received Graph Update: \(data.count) bytes")
    }
}
