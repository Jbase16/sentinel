// ============================================================================
// ui/Sources/Models/ChatModels.swift
// Chatmodels Component
// ============================================================================
//
// PURPOSE:
// This Swift component is part of the SentinelForge macOS UI.
// [Specific purpose based on component name: ChatModels]
//
// KEY RESPONSIBILITIES:
// - [Automatically generated - review and enhance based on actual functionality]
//
// INTEGRATION:
// - Used by: [To be documented]
// - Depends on: [To be documented]
//
// ============================================================================

import Foundation

// Minimal chat primitives borrowed from Helix so the UI can render streaming text.
// Kept intentionally small to make serialization and previews easy.
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

// Represents a single conversation tab/thread.
public struct ChatThread: Identifiable, Codable, Hashable {
    public let id: UUID
    public var title: String
    public var messages: [ChatMessage]
    public var lastUpdated: Date

    public init(id: UUID = UUID(), title: String, messages: [ChatMessage] = []) {
        self.id = id
        self.title = title
        self.messages = messages
        self.lastUpdated = Date()
    }

    public mutating func append(_ message: ChatMessage) {
        messages.append(message)
        lastUpdated = Date()
    }

    public mutating func clear() {
        messages.removeAll()
        lastUpdated = Date()
    }
}
