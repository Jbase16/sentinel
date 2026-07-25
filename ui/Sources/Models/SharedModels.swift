//
//  SharedModels.swift
//  SentinelForgeUI
//
//  Shared data models used across AppState, Reducers, and Views.
//

import Foundation

// MARK: - Navigation

public enum SidebarTab: String, CaseIterable, Identifiable {
    case dashboard = "Dashboard"
    case chat = "Command Deck"
    case graph = "Neural Graph"
    case settings = "Settings"

    public var id: String { rawValue }
}

// MARK: - Logging

public struct LogItem: Identifiable, Equatable {
    public let id: UUID
    public let text: String

    public init(id: UUID, text: String) {
        self.id = id
        self.text = text
    }
}

// MARK: - Scan State

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

    public init(
        state: ScanState,
        target: String?,
        sessionId: String?,
        phase: String?,
        toolsStarted: Int,
        toolsCompleted: Int,
        findingsCount: Int,
        startedAt: Date?,
        completedAt: Date?
    ) {
        self.state = state
        self.target = target
        self.sessionId = sessionId
        self.phase = phase
        self.toolsStarted = toolsStarted
        self.toolsCompleted = toolsCompleted
        self.findingsCount = findingsCount
        self.startedAt = startedAt
        self.completedAt = completedAt
    }
}

public enum ScanState: String, Codable, Equatable {
    case idle = "idle"
    case starting = "starting"
    case running = "running"
    case paused = "paused"
    case completing = "completing"
    case complete = "complete"
    case failed = "failed"
}

public struct ToolProgress: Identifiable, Equatable {
    public let id: String
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

    public init(
        id: String,
        name: String,
        startedAt: Date,
        completedAt: Date? = nil,
        exitCode: Int? = nil,
        findingsCount: Int
    ) {
        self.id = id
        self.name = name
        self.startedAt = startedAt
        self.completedAt = completedAt
        self.exitCode = exitCode
        self.findingsCount = findingsCount
    }
}

// MARK: - Chat

public struct ChatMessage: Identifiable, Codable, Hashable {
    public enum Role: String, Codable, Hashable {
        case user, assistant, system
    }

    public let id: UUID
    public let role: Role
    public var text: String
    public var timestamp: Date

    public init(id: UUID = UUID(), role: Role, text: String, timestamp: Date = Date()) {
        self.id = id
        self.role = role
        self.text = text
        self.timestamp = timestamp
    }
}

public struct ChatThread: Identifiable, Codable, Hashable {
    public let id: UUID
    public var title: String
    public var messages: [ChatMessage]
    public var lastUpdated: Date
    public var streamBuffer: String = ""

    public init(id: UUID = UUID(), title: String, messages: [ChatMessage] = []) {
        self.id = id
        self.title = title
        self.messages = messages
        self.lastUpdated = Date()
    }

    public mutating func append(_ message: ChatMessage) {
        messages.append(message)
        lastUpdated = Date()
        streamBuffer = ""  // Clear buffer on commit
    }

    public mutating func clear() {
        messages.removeAll()
        lastUpdated = Date()
        streamBuffer = ""
    }
}

// MARK: - Decisions

public struct Decision: Identifiable, Codable {
    public let id: String
    public let scanId: String?
    public let type: String
    public let selectedAction: String
    public let rationale: String
    public let confidence: Double
    public let alternatives: [String]?
    public let suppressed: [String]?
    public let sequence: Int?
    public let triggers: [String]?
    public let timestamp: Date
    public let evidence: [String: AnyCodable]?

    public init(
        id: String,
        scanId: String?,
        type: String,
        selectedAction: String,
        rationale: String,
        confidence: Double,
        alternatives: [String]?,
        suppressed: [String]?,
        sequence: Int?,
        triggers: [String]?,
        timestamp: Date,
        evidence: [String: AnyCodable]?
    ) {
        self.id = id
        self.scanId = scanId
        self.type = type
        self.selectedAction = selectedAction
        self.rationale = rationale
        self.confidence = confidence
        self.alternatives = alternatives
        self.suppressed = suppressed
        self.sequence = sequence
        self.triggers = triggers
        self.timestamp = timestamp
        self.evidence = evidence
    }
}
