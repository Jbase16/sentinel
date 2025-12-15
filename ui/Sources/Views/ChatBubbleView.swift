// ============================================================================
// ui/Sources/Views/ChatBubbleView.swift
// Chatbubbleview Component
// ============================================================================
//
// PURPOSE:
// This Swift component is part of the SentinelForge macOS UI.
// [Specific purpose based on component name: ChatBubbleView]
//
// KEY RESPONSIBILITIES:
// - [Automatically generated - review and enhance based on actual functionality]
//
// INTEGRATION:
// - Used by: [To be documented]
// - Depends on: [To be documented]
//
// ============================================================================

import SwiftUI

// Minimal bubble renderer; colors differentiate user vs assistant.
struct ChatBubbleView: View {
    let message: ChatMessage
    var isStreaming: Bool = false

    var body: some View {
        HStack {
            if message.role == .assistant { Spacer() }
            
            VStack(alignment: message.role == .user ? .trailing : .leading, spacing: 4) {
                if message.text.isEmpty && isStreaming {
                    HStack(spacing: 4) {
                        ProgressView()
                            .scaleEffect(0.6)
                        Text("Thinking...")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    .padding(10)
                    .background(Color.green.opacity(0.2))
                    .cornerRadius(10)
                } else {
                    Text(message.text)
                        .textSelection(.enabled)
                        .padding(10)
                        .background(message.role == .user ? Color.blue.opacity(0.2) : Color.green.opacity(0.2))
                        .cornerRadius(10)
                }
                
                // Show streaming indicator on assistant messages
                if isStreaming && !message.text.isEmpty {
                    HStack(spacing: 4) {
                        ProgressView()
                            .scaleEffect(0.5)
                        Text("Streaming...")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }
                }
            }
            
            if message.role == .user { Spacer() }
        }
    }
}
