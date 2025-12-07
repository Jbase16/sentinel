import SwiftUI

// Minimal bubble renderer; colors differentiate user vs assistant.
struct ChatBubbleView: View {
    let message: ChatMessage

    var body: some View {
        HStack {
            if message.role == .assistant { Spacer() }
            Text(message.text)
                .padding(10)
                .background(message.role == .user ? Color.blue.opacity(0.2) : Color.green.opacity(0.2))
                .cornerRadius(10)
            if message.role == .user { Spacer() }
        }
    }
}
