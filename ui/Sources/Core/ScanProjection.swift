//
//  ScanProjection.swift
//  SentinelForgeUI
//
//  SCAN PROJECTION: Derived State from Event Stream
//
//  This module implements a pure fold over the event stream to derive
//  scan state. It is NOT an independent state holder - it COMPUTES state.
//
//  DESIGN PRINCIPLES:
//  1. No @Published state that can drift from events
//  2. All state is derived: fold(events) → ScanProgress
//  3. Time-travel ready: replay events from any sequence to rebuild state
//  4. Testable: pure functions, no side effects
//
//  USAGE:
//      let projection = ScanProjection()
//      projection.apply(event)
//      if projection.isRunning { ... }
//

import Combine
import Foundation

// MARK: - Derived State Types

/// Immutable snapshot of scan progress, derived from events
public struct ScanProgress: Equatable {
    public let state: ScanState
    public let target: String?
    public let sessionId: String?
    public let phase: String?
    public let toolsStarted: Int
    public let toolsCompleted: Int
    public let findingsCount: Int
    public let startedAt: Date?
    public let completedAt: Date?

    /// Computed from state
    public var isRunning: Bool {
        switch state {
        case .starting, .running:
            return true
        default:
            return false
        }
    }

    public var isComplete: Bool {
        state == .complete || state == .failed
    }

    public var duration: TimeInterval? {
        guard let start = startedAt else { return nil }
        let end = completedAt ?? Date()
        return end.timeIntervalSince(start)
    }

    /// Initial state
    public static let idle = ScanProgress(
        state: .idle,
        target: nil,
        sessionId: nil,
        phase: nil,
        toolsStarted: 0,
        toolsCompleted: 0,
        findingsCount: 0,
        startedAt: nil,
        completedAt: nil
    )
}

/// Scan lifecycle states (mirrors Python ScanState)
public enum ScanState: String, Codable, Equatable {
    case idle = "idle"
    case starting = "starting"
    case running = "running"
    case paused = "paused"
    case completing = "completing"
    case complete = "complete"
    case failed = "failed"
}

/// Tool execution state
public struct ToolProgress: Identifiable, Equatable {
    public let id: String  // tool name
    public let name: String
    public let startedAt: Date
    public var completedAt: Date?
    public var exitCode: Int?
    public var findingsCount: Int

    public var isRunning: Bool { completedAt == nil }

    public var duration: TimeInterval? {
        guard let end = completedAt else { return nil }
        return end.timeIntervalSince(startedAt)
    }
}

// MARK: - Scan Projection (Pure Fold)

/// Pure projection of event stream into scan state
///
/// This class maintains an internal log of events and derives state
/// from the log. It NEVER holds state independently of the events.
///
/// Thread Safety:
/// - All mutations are on MainActor
/// - Published values update atomically
@MainActor
public class ScanProjection: ObservableObject {

    // MARK: - Observable State (Derived)

    /// Current scan progress (derived from events)
    @Published public private(set) var progress: ScanProgress = .idle

    /// Active tools (derived from events)
    @Published public private(set) var activeTools: [ToolProgress] = []

    /// All tools this session (derived from events)
    @Published public private(set) var toolHistory: [ToolProgress] = []

    // MARK: - Event Log (Source of Truth)

    private var events: [GraphEvent] = []
    private var toolStates: [String: ToolProgress] = [:]

    /// Apply an event and recompute state
    public func apply(_ event: GraphEvent) {
        events.append(event)
        recompute(from: event)
    }

    /// Replay from a sequence of events (for reconnection)
    public func replay(_ events: [GraphEvent]) {
        self.events = events
        self.toolStates.removeAll()

        // Full recompute from scratch
        var newProgress = ScanProgress.idle

        for event in events {
            newProgress = fold(state: newProgress, event: event)
        }

        self.progress = newProgress
        updateToolViews()
    }

    /// Reset to initial state
    public func reset() {
        events.removeAll()
        toolStates.removeAll()
        progress = .idle
        activeTools = []
        toolHistory = []
    }

    // MARK: - Pure Fold Function

    /// Pure state transition: (oldState, event) → newState
    private func fold(state: ScanProgress, event: GraphEvent) -> ScanProgress {
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
            let tool = event.payload["tool"]?.stringValue ?? "unknown"
            toolStates[tool] = ToolProgress(
                id: tool,
                name: tool,
                startedAt: Date(timeIntervalSince1970: event.timestamp),
                completedAt: nil,
                exitCode: nil,
                findingsCount: 0
            )
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
            let tool = event.payload["tool"]?.stringValue ?? "unknown"
            let exitCode = event.payload["exit_code"]?.intValue ?? 0
            let findings = event.payload["findings_count"]?.intValue ?? 0

            if var ts = toolStates[tool] {
                ts.completedAt = Date(timeIntervalSince1970: event.timestamp)
                ts.exitCode = exitCode
                ts.findingsCount = findings
                toolStates[tool] = ts
            }

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
            // Events that don't affect scan state
            return state
        }
    }

    // MARK: - Incremental Update

    /// Update state from a single new event (incremental, not full recompute)
    private func recompute(from event: GraphEvent) {
        progress = fold(state: progress, event: event)
        updateToolViews()
    }

    private func updateToolViews() {
        activeTools = toolStates.values.filter { $0.isRunning }.sorted {
            $0.startedAt < $1.startedAt
        }
        toolHistory = toolStates.values.sorted { $0.startedAt < $1.startedAt }
    }

    // MARK: - Convenience Queries

    /// Is a scan currently running?
    public var isRunning: Bool { progress.isRunning }

    /// Current scan target
    public var target: String? { progress.target }

    /// Current phase
    public var phase: String? { progress.phase }

    /// Total findings count
    public var findingsCount: Int { progress.findingsCount }
}
