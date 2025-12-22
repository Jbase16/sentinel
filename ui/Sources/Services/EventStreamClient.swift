//
// PURPOSE:
// This Swift component is part of the SentinelForge macOS UI.
// [Specific purpose based on component name: EventStreamClient]
//
// KEY RESPONSIBILITIES:
// - [Automatically generated - review and enhance based on actual functionality]
//
// INTEGRATION:
// - Used by: [To be documented]
// - Depends on: [To be documented]
//

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
public struct GraphEvent: Decodable, Identifiable, Equatable {
    public let id: String
    public let type: String
    public let timestamp: Double
    public let wall_time: String
    public let sequence: Int
    public let payload: [String: AnyCodable]
    public let source: String?  // Made optional: not all events have source

    /// Event type as enum for pattern matching
    public var eventType: GraphEventType {
        GraphEventType(rawValue: type) ?? .unknown
    }

    public static func == (lhs: GraphEvent, rhs: GraphEvent) -> Bool {
        lhs.id == rhs.id
    }
}

/// All known event types from the backend
public enum GraphEventType: String, CaseIterable {
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
    case scanFailed = "scan_failed"  // Aligned: was "scan_error"

    // Findings
    case findingCreated = "finding_created"  // Aligned: was "finding_discovered"
    case findingConfirmed = "finding_confirmed"
    case findingDismissed = "finding_dismissed"

    // Tool Execution
    case toolStarted = "tool_started"  // Aligned: was "tool_invoked"
    case toolCompleted = "tool_completed"

    // Logging & Reasoning
    case log = "log"  // Aligned: was "log_emitted"
    case narrativeEmitted = "narrative_emitted"
    case decisionMade = "decision_made"  // NEW: Added for Strategos decisions
    case actionNeeded = "action_needed"

    // Fallback
    case unknown = "unknown"
}

/// Type-erased Codable wrapper for heterogeneous payloads
public struct AnyCodable: Decodable {
    public let value: Any

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()

        // Conditional branch.
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
    public var stringValue: String? { value as? String }

    /// Get value as Int
    public var intValue: Int? { value as? Int }

    /// Get value as Double
    public var doubleValue: Double? { value as? Double }

    /// Get value as Bool
    public var boolValue: Bool? { value as? Bool }

    /// Get value as Dictionary
    public var dictValue: [String: Any]? { value as? [String: Any] }
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
public class EventStreamClient: ObservableObject {

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
        // Guard condition.
        guard task == nil else { return }

        task = Task { [weak self] in
            await self?.connectionLoop()
        }
    }

    /// Stop consuming and disconnect
    nonisolated func disconnect() {
        Task { @MainActor in
            self.task?.cancel()
            self.task = nil
            self.isConnected = false
        }
    }

    // MARK: - Connection Loop

    private func connectionLoop() async {
        // While loop.
        while !Task.isCancelled && reconnectAttempt < maxReconnectAttempts {
            // Do-catch block.
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

        // Conditional branch.
        if reconnectAttempt >= maxReconnectAttempts {
            print("[EventStreamClient] Max reconnect attempts reached")
        }
    }

    private func consumeStream() async throws {
        let url = baseURL.appendingPathComponent("/events/stream")
        var components = URLComponents(url: url, resolvingAgainstBaseURL: false)!
        components.queryItems = [URLQueryItem(name: "since", value: "\(lastSequence)")]

        // Guard condition.
        guard let finalURL = components.url else {
            throw URLError(.badURL)
        }

        var request = URLRequest(url: finalURL)
        request.setValue("text/event-stream", forHTTPHeaderField: "Accept")
        request.setValue("Bearer dev-token", forHTTPHeaderField: "Authorization")
        request.timeoutInterval = 60 * 60  // 1 hour timeout

        let (bytes, response) = try await URLSession.shared.bytes(for: request)

        // Guard condition.
        guard let httpResponse = response as? HTTPURLResponse,
            httpResponse.statusCode == 200
        else {
            throw URLError(.badServerResponse)
        }

        // REMOVED: isConnected = true (now handled in handleEvent after first event)
        reconnectAttempt = 0
        print("[EventStreamClient] Connected, replaying from sequence \(lastSequence)")

        // Parse SSE stream
        // Track the current SSE event type for filtering control events
        var currentEventType: String? = nil

        for try await line in bytes.lines {
            // Conditional branch.
            if Task.isCancelled { break }

            // Track SSE event type (e.g., "event: warning")
            if line.hasPrefix("event:") {
                currentEventType = line.dropFirst(6).trimmingCharacters(in: .whitespaces)
                continue
            }

            // Conditional branch.
            if line.hasPrefix("data:") {
                // Skip control events like "warning" that aren't GraphEvents
                if currentEventType == "warning" {
                    let json = line.dropFirst(5).trimmingCharacters(in: .whitespaces)
                    print(
                        "[EventStreamClient] Control event (\(currentEventType ?? "unknown")): \(json)"
                    )
                    currentEventType = nil
                    continue
                }

                let json = line.dropFirst(5).trimmingCharacters(in: .whitespaces)
                currentEventType = nil  // Reset for next event

                // Guard condition.
                guard let data = json.data(using: .utf8) else { continue }

                // Do-catch block.
                do {
                    let event = try JSONDecoder().decode(GraphEvent.self, from: data)
                    await handleEvent(event)
                } catch {
                    print("[EventStreamClient] Decode error: \(error)")
                    print("[EventStreamClient] Raw JSON: \(json)")
                }
            }
        }
    }

    // MARK: - Event Handling

    private func handleEvent(_ event: GraphEvent) async {
        // Mark as connected on first event receipt
        if !isConnected {
            isConnected = true
        }

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

        case .log:
            logEventPublisher.send(event)

        case .findingCreated, .findingConfirmed, .findingDismissed:
            findingEventPublisher.send(event)

        case .scanStarted, .scanPhaseChanged, .scanCompleted, .scanFailed, .toolStarted,
            .toolCompleted, .narrativeEmitted, .decisionMade, .actionNeeded:
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
