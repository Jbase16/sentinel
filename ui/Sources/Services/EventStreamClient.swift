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
    public let epoch: String?  // Server process epoch - changes on restart

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
    case scanFailed = "scan_failed"

    // Findings
    case findingCreated = "finding_created"
    case findingConfirmed = "finding_confirmed"
    case findingDismissed = "finding_dismissed"
    case findingDiscovered = "finding_discovered"  // NEW: Lazarus hidden routes

    // Tool Execution
    case toolStarted = "tool_started"
    case toolCompleted = "tool_completed"

    // Logging & Reasoning
    case log = "log"
    case narrativeEmitted = "narrative_emitted"
    case decisionMade = "decision_made"
    case actionNeeded = "action_needed"

    // Trinity of Hardening Events
    case circuitBreakerStateChanged = "circuit_breaker_state"  // NEW: AI fuse state
    case exploitValidated = "exploit_validated"  // NEW: Forge approved
    case exploitRejected = "exploit_rejected"  // NEW: Forge rejected

    // Cortex / Doppelganger Events (SCREAMING_SNAKE match)
    case breachDetected = "BREACH_DETECTED"
    case identityEstablished = "IDENTITY_ESTABLISHED"

    // Diagnostic / Governance Events (internal events, handled gracefully)
    case contractViolation = "contract_violation"
    case orphanEventDropped = "orphan_event_dropped"
    case resourceGuardTrip = "resource_guard_trip"
    case eventSilence = "event_silence"
    case toolChurn = "tool_churn"

    // Fallback
    case unknown = "unknown"
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

    /// Last known server epoch (detects server restarts)
    @Published private(set) var lastKnownEpoch: String? = nil

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

    /// Path to the token file (mirrors SentinelAPIClient)
    private static let tokenPath: URL = {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".sentinelforge")
            .appendingPathComponent("api_token")
    }()

    private static func readToken() -> String? {
        try? String(contentsOf: tokenPath, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

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

    /// Force reconnect by cancelling the current task and starting a new one.
    func reconnectNow() {
        disconnect()
        reconnectAttempt = 0
        connect()
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

                // Log error only if it's a real error (not connection refused during startup)
                if ErrorClassifier.shouldLogAsError(error) {
                    print("[EventStreamClient] Error: \(error.localizedDescription)")
                }

                // Custom backoff: 0, 0.2, 0.5, 1.0, 5.0 seconds
                reconnectAttempt += 1
                let delay = RetryBackoff.delayForAttempt(reconnectAttempt)

                let logMessage: String
                if ErrorClassifier.isConnectionRefused(error) {
                    logMessage = "Backend starting, retrying..."
                } else {
                    logMessage = "Reconnecting..."
                }

                print(
                    "[EventStreamClient] \(logMessage) in \(String(format: "%.1f", delay))s (attempt \(reconnectAttempt))"
                )
                await RetryBackoff.sleep(for: reconnectAttempt)
            }
        }

        // Conditional branch.
        if reconnectAttempt >= maxReconnectAttempts {
            print("[EventStreamClient] Max reconnect attempts reached")
        }
    }

    private func consumeStream() async throws {
        let url = baseURL.appendingPathComponent("/v1/events/stream")
        var components = URLComponents(url: url, resolvingAgainstBaseURL: false)!
        components.queryItems = [URLQueryItem(name: "since", value: "\(lastSequence)")]

        // Guard condition.
        guard let finalURL = components.url else {
            throw URLError(.badURL)
        }

        var request = URLRequest(url: finalURL)
        request.setValue("text/event-stream", forHTTPHeaderField: "Accept")

        // Read auth token from standard location
        if let token = Self.readToken() {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

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

        if !Task.isCancelled {
            isConnected = false
        }
    }

    // MARK: - Event Handling

    private func handleEvent(_ event: GraphEvent) async {
        // Mark as connected on first event receipt
        if !isConnected {
            isConnected = true
        }

        // EPOCH DETECTION: Server restart resets sequence counters.
        // If epoch changes, we must reset our state to avoid silent event drops.
        if let eventEpoch = event.epoch {
            if let knownEpoch = lastKnownEpoch, knownEpoch != eventEpoch {
                // Server restarted! Reset state to avoid deduplication errors.
                print("[EventStreamClient] ⚠️ Epoch changed: \(knownEpoch) -> \(eventEpoch)")
                print("[EventStreamClient] Resetting sequence tracking (server restarted)")
                lastSequence = 0
                eventCount = 0
            }
            lastKnownEpoch = eventEpoch
            persistEpoch()
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

        case .findingCreated, .findingConfirmed, .findingDismissed, .findingDiscovered:
            findingEventPublisher.send(event)

        case .scanStarted, .scanPhaseChanged, .scanCompleted, .scanFailed, .toolStarted,
            .toolCompleted, .narrativeEmitted, .decisionMade, .actionNeeded:
            scanEventPublisher.send(event)

        case .circuitBreakerStateChanged, .exploitValidated, .exploitRejected:
            // Trinity of Hardening events - publish to scan stream for status updates
            scanEventPublisher.send(event)

        case .breachDetected, .identityEstablished:
            // Critical Identity/Security events - broadcast to scan stream (where HelixAppState listens)
            scanEventPublisher.send(event)

        case .contractViolation, .orphanEventDropped, .resourceGuardTrip, .eventSilence, .toolChurn:
            // Diagnostic / Governance events - handled gracefully, not shown to user
            // These are internal events for monitoring and debugging
            break

        case .unknown:
            print("[EventStreamClient] Unknown event type: \(event.type)")
        }
    }

    // MARK: - Persistence

    private let sequenceKey = "EventStreamClient.lastSequence"
    private let epochKey = "EventStreamClient.lastEpoch"

    private func loadPersistedSequence() {
        lastSequence = UserDefaults.standard.integer(forKey: sequenceKey)
        lastKnownEpoch = UserDefaults.standard.string(forKey: epochKey)
    }

    private func persistSequence() {
        // Throttle writes (every 10 events)
        if eventCount % 10 == 0 {
            UserDefaults.standard.set(lastSequence, forKey: sequenceKey)
        }
    }

    private func persistEpoch() {
        if let epoch = lastKnownEpoch {
            UserDefaults.standard.set(epoch, forKey: epochKey)
        }
    }

    /// Reset the sequence to replay all events
    func resetSequence() {
        lastSequence = 0
        eventCount = 0
        lastKnownEpoch = nil
        UserDefaults.standard.removeObject(forKey: sequenceKey)
        UserDefaults.standard.removeObject(forKey: epochKey)
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
