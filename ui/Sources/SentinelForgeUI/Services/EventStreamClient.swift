//
//  EventStreamClient.swift
//  SentinelForgeUI
//
//  Event-Sourced Reactive Graph: Swift Client
//  Consumes the unified SSE stream from /events/stream
//

import Combine
import Foundation

// MARK: - Event Models

/// Typed event received from the backend EventStore
struct GraphEvent: Decodable, Identifiable {
    let id: String
    let type: String
    let timestamp: Double
    let wall_time: String
    let sequence: Int
    let payload: [String: AnyCodable]
    let source: String

    /// Event type as enum for pattern matching
    var eventType: GraphEventType {
        GraphEventType(rawValue: type) ?? .unknown
    }
}

/// All known event types from the backend
enum GraphEventType: String, CaseIterable {
    // Graph Structure
    case nodeAdded = "node_added"
    case nodeUpdated = "node_updated"
    case nodeRemoved = "node_removed"
    case edgeAdded = "edge_added"
    case edgeUpdated = "edge_updated"

    // Scan Lifecycle
    case scanStarted = "scan_started"
    case scanPhaseChanged = "scan_phase_changed"
    case scanCompleted = "scan_completed"
    case scanError = "scan_error"

    // Findings
    case findingDiscovered = "finding_discovered"
    case findingConfirmed = "finding_confirmed"
    case findingDismissed = "finding_dismissed"

    // Tool Execution
    case toolInvoked = "tool_invoked"
    case toolCompleted = "tool_completed"

    // Logging
    case logEmitted = "log_emitted"

    // Fallback
    case unknown = "unknown"
}

/// Type-erased Codable wrapper for heterogeneous payloads
struct AnyCodable: Decodable {
    let value: Any

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()

        if let string = try? container.decode(String.self) {
            value = string
        } else if let int = try? container.decode(Int.self) {
            value = int
        } else if let double = try? container.decode(Double.self) {
            value = double
        } else if let bool = try? container.decode(Bool.self) {
            value = bool
        } else if let dict = try? container.decode([String: AnyCodable].self) {
            value = dict.mapValues { $0.value }
        } else if let array = try? container.decode([AnyCodable].self) {
            value = array.map { $0.value }
        } else if container.decodeNil() {
            value = NSNull()
        } else {
            throw DecodingError.dataCorruptedError(
                in: container, debugDescription: "Unsupported type")
        }
    }

    /// Get value as String
    var stringValue: String? { value as? String }

    /// Get value as Int
    var intValue: Int? { value as? Int }

    /// Get value as Double
    var doubleValue: Double? { value as? Double }

    /// Get value as Bool
    var boolValue: Bool? { value as? Bool }

    /// Get value as Dictionary
    var dictValue: [String: Any]? { value as? [String: Any] }
}

// MARK: - EventStreamClient

/// Reactive client for the /events/stream SSE endpoint
///
/// This client:
/// 1. Connects to the backend SSE stream
/// 2. Automatically replays missed events on reconnection
/// 3. Publishes typed events to subscribers
/// 4. Persists the last seen sequence for reconnection
///
/// Usage:
/// ```swift
/// let client = EventStreamClient()
/// for await event in client.events {
///     switch event.eventType {
///     case .nodeAdded:
///         handleNodeAdded(event.payload)
///     // ...
///     }
/// }
/// ```
@MainActor
class EventStreamClient: ObservableObject {

    // MARK: - Published State

    /// Whether the client is currently connected
    @Published private(set) var isConnected = false

    /// Last error encountered
    @Published private(set) var lastError: Error?

    /// Last received sequence number (for reconnection)
    @Published private(set) var lastSequence: Int = 0

    /// Event count since connection
    @Published private(set) var eventCount: Int = 0

    // MARK: - Event Publishers

    /// All events
    let eventPublisher = PassthroughSubject<GraphEvent, Never>()

    /// Node events only (for graph visualization)
    let graphEventPublisher = PassthroughSubject<GraphEvent, Never>()

    /// Log events only (for console)
    let logEventPublisher = PassthroughSubject<GraphEvent, Never>()

    /// Finding events only (for findings list)
    let findingEventPublisher = PassthroughSubject<GraphEvent, Never>()

    /// Scan lifecycle events
    let scanEventPublisher = PassthroughSubject<GraphEvent, Never>()

    // MARK: - Private

    private var task: Task<Void, Never>?
    private let baseURL: URL
    private var reconnectAttempt = 0
    private let maxReconnectAttempts = 10
    private let reconnectBaseDelay: TimeInterval = 1.0

    // MARK: - Initialization

    init(baseURL: URL = URL(string: "http://127.0.0.1:8765")!) {
        self.baseURL = baseURL
        loadPersistedSequence()
    }

    deinit {
        disconnect()
    }

    // MARK: - Connection

    /// Start consuming the event stream
    func connect() {
        guard task == nil else { return }

        task = Task { [weak self] in
            await self?.connectionLoop()
        }
    }

    /// Stop consuming and disconnect
    func disconnect() {
        task?.cancel()
        task = nil
        isConnected = false
    }

    // MARK: - Connection Loop

    private func connectionLoop() async {
        while !Task.isCancelled && reconnectAttempt < maxReconnectAttempts {
            do {
                try await consumeStream()
                // If we exit cleanly, reset reconnect counter
                reconnectAttempt = 0
            } catch {
                lastError = error
                isConnected = false

                // Exponential backoff with jitter
                let delay =
                    reconnectBaseDelay * pow(2.0, Double(reconnectAttempt))
                    + Double.random(in: 0...0.5)
                reconnectAttempt += 1

                print(
                    "[EventStreamClient] Reconnecting in \(String(format: "%.1f", delay))s (attempt \(reconnectAttempt))"
                )
                try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            }
        }

        if reconnectAttempt >= maxReconnectAttempts {
            print("[EventStreamClient] Max reconnect attempts reached")
        }
    }

    private func consumeStream() async throws {
        let url = baseURL.appendingPathComponent("/events/stream")
        var components = URLComponents(url: url, resolvingAgainstBaseURL: false)!
        components.queryItems = [URLQueryItem(name: "since", value: "\(lastSequence)")]

        guard let finalURL = components.url else {
            throw URLError(.badURL)
        }

        var request = URLRequest(url: finalURL)
        request.setValue("text/event-stream", forHTTPHeaderField: "Accept")
        request.setValue("Bearer dev-token", forHTTPHeaderField: "Authorization")
        request.timeoutInterval = 60 * 60  // 1 hour timeout

        let (bytes, response) = try await URLSession.shared.bytes(for: request)

        guard let httpResponse = response as? HTTPURLResponse,
            httpResponse.statusCode == 200
        else {
            throw URLError(.badServerResponse)
        }

        isConnected = true
        reconnectAttempt = 0
        print("[EventStreamClient] Connected, replaying from sequence \(lastSequence)")

        // Parse SSE stream
        var eventType: String?
        var dataBuffer = ""

        for try await line in bytes.lines {
            if Task.isCancelled { break }

            if line.isEmpty {
                // Empty line = end of event
                if let data = dataBuffer.data(using: .utf8),
                    let event = try? JSONDecoder().decode(GraphEvent.self, from: data)
                {
                    await handleEvent(event)
                }
                eventType = nil
                dataBuffer = ""
            } else if line.hasPrefix("event:") {
                eventType = String(line.dropFirst(6)).trimmingCharacters(in: .whitespaces)
            } else if line.hasPrefix("data:") {
                let dataLine = String(line.dropFirst(5)).trimmingCharacters(in: .whitespaces)
                dataBuffer += dataLine
            } else if line.hasPrefix(":") {
                // Comment/keepalive, ignore
            }
        }
    }

    // MARK: - Event Handling

    private func handleEvent(_ event: GraphEvent) async {
        // Update tracking
        lastSequence = max(lastSequence, event.sequence)
        eventCount += 1
        persistSequence()

        // Publish to all-events stream
        eventPublisher.send(event)

        // Route to specific publishers
        switch event.eventType {
        case .nodeAdded, .nodeUpdated, .nodeRemoved, .edgeAdded, .edgeUpdated:
            graphEventPublisher.send(event)

        case .logEmitted:
            logEventPublisher.send(event)

        case .findingDiscovered, .findingConfirmed, .findingDismissed:
            findingEventPublisher.send(event)

        case .scanStarted, .scanPhaseChanged, .scanCompleted, .scanError, .toolInvoked,
            .toolCompleted:
            scanEventPublisher.send(event)

        case .unknown:
            print("[EventStreamClient] Unknown event type: \(event.type)")
        }
    }

    // MARK: - Persistence

    private let sequenceKey = "EventStreamClient.lastSequence"

    private func loadPersistedSequence() {
        lastSequence = UserDefaults.standard.integer(forKey: sequenceKey)
    }

    private func persistSequence() {
        // Throttle writes (every 10 events)
        if eventCount % 10 == 0 {
            UserDefaults.standard.set(lastSequence, forKey: sequenceKey)
        }
    }

    /// Reset the sequence to replay all events
    func resetSequence() {
        lastSequence = 0
        eventCount = 0
        UserDefaults.standard.removeObject(forKey: sequenceKey)
    }
}

// MARK: - AsyncSequence Support

extension EventStreamClient {
    /// Async sequence of all events
    var events: AsyncStream<GraphEvent> {
        AsyncStream { continuation in
            let cancellable = eventPublisher.sink { event in
                continuation.yield(event)
            }

            continuation.onTermination = { _ in
                cancellable.cancel()
            }
        }
    }

    /// Async sequence of graph events only
    var graphEvents: AsyncStream<GraphEvent> {
        AsyncStream { continuation in
            let cancellable = graphEventPublisher.sink { event in
                continuation.yield(event)
            }

            continuation.onTermination = { _ in
                cancellable.cancel()
            }
        }
    }
}
