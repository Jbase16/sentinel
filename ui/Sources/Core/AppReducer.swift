//
//  AppReducer.swift
//  SentinelForgeUI
//
//  UNIFIED REDUCER: Centralized Event → State Transformation
//
//  This module implements a pure reducer function that handles ALL events
//  in ONE place. No more scattered event handling in multiple views.
//
//  DESIGN PRINCIPLES:
//  1. Pure function: (State, Event) → State (no side effects)
//  2. Exhaustive: Every event type has explicit handling
//  3. Composable: Sub-reducers for different state slices
//  4. Testable: Can replay any event sequence to reproduce state
//
//  ARCHITECTURE:
//
//      EventStreamClient
//            │
//            ▼
//      ┌─────────────┐
//      │  AppReducer │ ◄── Pure function
//      └─────────────┘
//            │
//            ▼
//      ┌─────────────┐
//      │  AppState   │ ◄── ObservableObject
//      └─────────────┘
//            │
//            ▼
//        SwiftUI Views
//

import Combine
import Foundation

// MARK: - App State Slices

/// Complete UI state (immutable snapshot)
public struct AppStateSnapshot: Equatable {
    // Scan state
    public var scan: ScanProgress

    // Logs
    public var logItems: [LogItem]

    // Findings summary
    public var findingsCount: Int

    // Connection status
    public var isConnected: Bool
    public var lastEventSequence: Int

    // UI state
    public var activeTab: SidebarTab

    public static let initial = AppStateSnapshot(
        scan: .idle,
        logItems: [],
        findingsCount: 0,
        isConnected: false,
        lastEventSequence: 0,
        activeTab: .dashboard
    )
}

// MARK: - Reducer Actions

/// All possible actions that can modify state
public enum AppAction: Equatable {
    // Event stream
    case eventReceived(GraphEvent)
    case connectionStateChanged(isConnected: Bool)

    // User actions
    case tabSelected(SidebarTab)
    case clearLogs
    case resetSequence
}

// MARK: - Pure Reducer Function

/// The core reducer: (State, Action) → State
///
/// This is a PURE FUNCTION - no side effects allowed.
/// All state changes must go through this function.
///
/// Benefits:
/// - Testable: Just call reduce() with any state/action
/// - Debuggable: Log every action and resulting state
/// - Replayable: Save actions to reproduce bugs
public func appReducer(state: AppStateSnapshot, action: AppAction) -> AppStateSnapshot {
    var newState = state

    switch action {
    case .eventReceived(let event):
        newState = reduceEvent(state: state, event: event)

    case .connectionStateChanged(let isConnected):
        newState.isConnected = isConnected

    case .tabSelected(let tab):
        newState.activeTab = tab

    case .clearLogs:
        newState.logItems = []

    case .resetSequence:
        newState.lastEventSequence = 0
        newState.scan = .idle
        newState.logItems = []
    }

    return newState
}

// MARK: - Event Sub-Reducer

/// Handle a single GraphEvent and update state
private func reduceEvent(state: AppStateSnapshot, event: GraphEvent) -> AppStateSnapshot {
    var newState = state

    // Update sequence tracking
    newState.lastEventSequence = max(state.lastEventSequence, event.sequence)

    // Apply to scan projection
    newState.scan = reduceScan(state: state.scan, event: event)

    // Generate log item if appropriate
    if let logText = renderLogLine(event: event) {
        let logItem = LogItem(id: UUID(), text: logText)
        newState.logItems.append(logItem)

        // Cap log size to prevent memory issues
        if newState.logItems.count > 1000 {
            newState.logItems.removeFirst(100)
        }
    }

    // Update findings count from scan projection
    newState.findingsCount = newState.scan.findingsCount

    return newState
}

// MARK: - Scan Sub-Reducer

/// Pure fold for scan state (mirrors ScanProjection.fold)
private func reduceScan(state: ScanProgress, event: GraphEvent) -> ScanProgress {
    switch event.eventType {
    case .scanStarted:
        let target = event.payload["target"]?.stringValue ?? "unknown"
        let sessionId = event.payload["session_id"]?.stringValue
        return ScanProgress(
            state: .running,
            target: target,
            sessionId: sessionId,
            phase: nil,
            toolsStarted: 0,
            toolsCompleted: 0,
            findingsCount: 0,
            startedAt: Date(timeIntervalSince1970: event.timestamp),
            completedAt: nil
        )

    case .scanPhaseChanged:
        let phase = event.payload["phase"]?.stringValue
        return ScanProgress(
            state: state.state,
            target: state.target,
            sessionId: state.sessionId,
            phase: phase,
            toolsStarted: state.toolsStarted,
            toolsCompleted: state.toolsCompleted,
            findingsCount: state.findingsCount,
            startedAt: state.startedAt,
            completedAt: state.completedAt
        )

    case .toolStarted:
        return ScanProgress(
            state: state.state,
            target: state.target,
            sessionId: state.sessionId,
            phase: state.phase,
            toolsStarted: state.toolsStarted + 1,
            toolsCompleted: state.toolsCompleted,
            findingsCount: state.findingsCount,
            startedAt: state.startedAt,
            completedAt: state.completedAt
        )

    case .toolCompleted:
        let findings = event.payload["findings_count"]?.intValue ?? 0
        return ScanProgress(
            state: state.state,
            target: state.target,
            sessionId: state.sessionId,
            phase: state.phase,
            toolsStarted: state.toolsStarted,
            toolsCompleted: state.toolsCompleted + 1,
            findingsCount: state.findingsCount + findings,
            startedAt: state.startedAt,
            completedAt: state.completedAt
        )

    case .scanCompleted:
        return ScanProgress(
            state: .complete,
            target: state.target,
            sessionId: state.sessionId,
            phase: state.phase,
            toolsStarted: state.toolsStarted,
            toolsCompleted: state.toolsCompleted,
            findingsCount: state.findingsCount,
            startedAt: state.startedAt,
            completedAt: Date(timeIntervalSince1970: event.timestamp)
        )

    case .scanFailed:
        return ScanProgress(
            state: .failed,
            target: state.target,
            sessionId: state.sessionId,
            phase: state.phase,
            toolsStarted: state.toolsStarted,
            toolsCompleted: state.toolsCompleted,
            findingsCount: state.findingsCount,
            startedAt: state.startedAt,
            completedAt: Date(timeIntervalSince1970: event.timestamp)
        )

    default:
        return state
    }
}

// MARK: - Log Rendering

/// Render an event into a human-readable log line
private func renderLogLine(event: GraphEvent) -> String? {
    switch event.eventType {
    case .log:
        return event.payload["message"]?.stringValue
            ?? event.payload["line"]?.stringValue

    case .scanStarted:
        let target = event.payload["target"]?.stringValue ?? "unknown"
        let toolCount = (event.payload["allowed_tools"]?.value as? [Any])?.count ?? 0
        return "🚀 [Scan] started: \(target) (\(toolCount) tools)"

    case .scanCompleted:
        let status = event.payload["status"]?.stringValue ?? "success"
        let findings = event.payload["findings_count"]?.intValue ?? 0
        let duration = event.payload["duration_seconds"]?.doubleValue ?? 0.0
        return String(
            format: "✅ [Scan] %@ (findings=%d, duration=%.1fs)", status, findings, duration)

    case .scanFailed:
        let error = event.payload["error"]?.stringValue ?? "unknown error"
        return "❌ [Scan] failed: \(error)"

    case .toolStarted:
        let tool = event.payload["tool"]?.stringValue ?? "unknown"
        return "🔧 [\(tool)] started"

    case .toolCompleted:
        let tool = event.payload["tool"]?.stringValue ?? "unknown"
        let exitCode = event.payload["exit_code"]?.intValue ?? 0
        let findings = event.payload["findings_count"]?.intValue ?? 0
        let status = exitCode == 0 ? "✓" : "✗"
        return "\(status) [\(tool)] done (findings=\(findings))"

    case .narrativeEmitted:
        let narrative = event.payload["narrative"]?.stringValue ?? "..."
        return "🧠 \(narrative)"

    case .decisionMade:
        let intent = event.payload["intent"]?.stringValue ?? "unknown"
        let reason = event.payload["reason"]?.stringValue ?? ""
        return "💡 [Decision] \(intent): \(reason)"

    case .scanPhaseChanged:
        let phase = event.payload["phase"]?.stringValue ?? "unknown"
        return "🔄 [Phase] → \(phase)"

    default:
        return nil
    }
}

// MARK: - Store (Observable Wrapper)

/// Observable store that wraps the pure reducer
///
/// This is the ONLY class that holds mutable state. It:
/// 1. Receives actions from UI
/// 2. Calls the pure reducer
/// 3. Publishes new state to subscribers
@MainActor
public class AppStore: ObservableObject {

    @Published public private(set) var state: AppStateSnapshot = .initial

    /// Dispatch an action to update state
    public func dispatch(_ action: AppAction) {
        state = appReducer(state: state, action: action)
    }

    /// Convenience: dispatch event directly
    public func apply(_ event: GraphEvent) {
        dispatch(.eventReceived(event))
    }

    /// Connect to event stream and auto-dispatch events
    public func connect(to eventClient: EventStreamClient) {
        // Subscribe to all events
        eventClient.eventPublisher
            .receive(on: RunLoop.main)
            .sink { [weak self] event in
                self?.apply(event)
            }
            .store(in: &cancellables)

        // Track connection state
        eventClient.$isConnected
            .receive(on: RunLoop.main)
            .sink { [weak self] isConnected in
                self?.dispatch(.connectionStateChanged(isConnected: isConnected))
            }
            .store(in: &cancellables)
    }

    private var cancellables = Set<AnyCancellable>()

    // MARK: - Convenience Accessors

    public var isRunning: Bool { state.scan.isRunning }
    public var target: String? { state.scan.target }
    public var phase: String? { state.scan.phase }
    public var findingsCount: Int { state.findingsCount }
    public var logItems: [LogItem] { state.logItems }
    public var isConnected: Bool { state.isConnected }
}
