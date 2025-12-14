import Foundation

// Minimal chat primitives borrowed from Helix so the UI can render streaming text.
// Kept intentionally small to make serialization and previews easy.
struct ChatMessage: Identifiable, Codable, Hashable {
    enum Role: String, Codable, Hashable {
        case user, assistant, system
    }

    let id: UUID
    let role: Role
    var text: String
    var timestamp: Date

    init(id: UUID = UUID(), role: Role, text: String, timestamp: Date = Date()) {
        self.id = id
        self.role = role
        self.text = text
        self.timestamp = timestamp
    }
}

// Represents a single conversation tab/thread.
struct ChatThread: Identifiable, Codable, Hashable {
    let id: UUID
    var title: String
    var messages: [ChatMessage]
    var lastUpdated: Date

    init(id: UUID = UUID(), title: String, messages: [ChatMessage] = []) {
        self.id = id
        self.title = title
        self.messages = messages
        self.lastUpdated = Date()
    }

    mutating func append(_ message: ChatMessage) {
        messages.append(message)
        lastUpdated = Date()
    }

    mutating func clear() {
        messages.removeAll()
        lastUpdated = Date()
    }
}
