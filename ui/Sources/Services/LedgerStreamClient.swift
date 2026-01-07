import Foundation
import Combine

// MARK: - Models

public struct EpistemicEvent: Decodable, Identifiable {
    public let id: String
    public let event_type: String
    public let entity_id: String
    public let payload: [String: AnyCodable]
    public let timestamp: Double
    public let source_component: String?
    
    // Helper for UI icons
    public var iconName: String {
        switch event_type {
        case "promoted": return "checkmark.seal.fill"
        case "suppressed": return "hand.raised.fill"
        case "conflict": return "exclamationmark.triangle.fill"
        case "observed": return "eye.fill"
        case "invalidated": return "xmark.bin.fill"
        default: return "circle"
        }
    }
}

// MARK: - Client

@MainActor
public class LedgerStreamClient: ObservableObject {
    @Published public var events: [EpistemicEvent] = []
    @Published public var isConnected: Bool = false
    
    private var webSocketTask: URLSessionWebSocketTask?
    private let url = URL(string: "ws://127.0.0.1:8000/v1/ws/events")!
    
    public init() {
        connect()
    }
    
    public func connect() {
        let session = URLSession(configuration: .default)
        webSocketTask = session.webSocketTask(with: url)
        webSocketTask?.resume()
        self.isConnected = true
        
        receiveMessage()
    }
    
    public func disconnect() {
        webSocketTask?.cancel(with: .goingAway, reason: nil)
        self.isConnected = false
    }
    
    private func receiveMessage() {
        webSocketTask?.receive { [weak self] result in
            guard let self = self else { return }
            
            switch result {
            case .failure(let error):
                print("[Ledger] WS Error: \(error)")
                DispatchQueue.main.async {
                    self.isConnected = false
                    // Simple reconnect after 3s
                    DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
                        self.connect()
                    }
                }
            case .success(let message):
                switch message {
                case .string(let text):
                    self.handleMessage(text)
                case .data(let data):
                    if let text = String(data: data, encoding: .utf8) {
                        self.handleMessage(text)
                    }
                @unknown default:
                    break
                }
                self.receiveMessage() // Loop
            }
        }
    }
    
    private func handleMessage(_ json: String) {
        guard let data = json.data(using: .utf8) else { return }
        do {
            let event = try JSONDecoder().decode(EpistemicEvent.self, from: data)
            DispatchQueue.main.async {
                self.events.insert(event, at: 0)
                if self.events.count > 200 { self.events.removeLast() }
            }
        } catch {
            print("[Ledger] Decode Error: \(error)")
        }
    }
}
