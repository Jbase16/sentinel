import Combine
import Foundation

// MARK: - Models

// GraphEvent and GraphEventType are now imported from EventStreamClient.swift

// MARK: - Client

@MainActor
public class LedgerStreamClient: ObservableObject {
    @Published public var events: [GraphEvent] = []
    @Published public var isConnected: Bool = false

    private var webSocketTask: URLSessionWebSocketTask?
    private let url = URL(string: "ws://127.0.0.1:8765/ws/events")!

    public init() {
        connect()
    }

    public func connect() {
        // Read auth token from standard location
        let tokenUrl = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".sentinelforge")
            .appendingPathComponent("api_token")

        var urlComponents = URLComponents(url: url, resolvingAgainstBaseURL: false)!

        if let token = try? String(contentsOf: tokenUrl, encoding: .utf8).trimmingCharacters(
            in: .whitespacesAndNewlines)
        {
            urlComponents.queryItems = [URLQueryItem(name: "token", value: token)]
        }

        guard let finalURL = urlComponents.url else { return }
        let request = URLRequest(url: finalURL)

        let session = URLSession(configuration: .default)
        webSocketTask = session.webSocketTask(with: request)
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
                Task { @MainActor in
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
                    self.receiveMessage()  // Loop
                }
            }
        }
    }

    private func handleMessage(_ json: String) {
        guard let data = json.data(using: .utf8) else { return }
        do {
            let event = try JSONDecoder().decode(GraphEvent.self, from: data)
            DispatchQueue.main.async {
                self.events.insert(event, at: 0)
                if self.events.count > 200 { self.events.removeLast() }
            }
        } catch {
            print("[Ledger] Decode Error: \(error)")
            print("[Ledger] Raw JSON: \(json)")
        }
    }
}
