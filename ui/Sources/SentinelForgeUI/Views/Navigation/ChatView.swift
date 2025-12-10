import SwiftUI

struct ChatView: View {
    @EnvironmentObject var appState: HelixAppState
    @State private var input: String = ""
    
    var body: some View {
        VStack(spacing: 0) {
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 12) {
                        ForEach(appState.thread.messages) { msg in
                            ChatBubbleView(message: msg)
                                .id(msg.id)
                        }
                    }
                    .padding()
                }
                .onChange(of: appState.thread.messages.count) { _ in
                    if let last = appState.thread.messages.last {
                        withAnimation {
                            proxy.scrollTo(last.id, anchor: .bottom)
                        }
                    }
                }
            }
            
            Divider()
            
            HStack(alignment: .bottom) {
                TextEditor(text: $input)
                    .frame(minHeight: 30, maxHeight: 100)
                    .padding(4)
                    .background(Color(NSColor.textBackgroundColor))
                    .cornerRadius(6)
                    .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.gray.opacity(0.3)))
                
                Button(action: sendMessage) {
                    Image(systemName: "paperplane.fill")
                        .font(.title2)
                        .foregroundColor(.blue)
                }
                .buttonStyle(.plain)
                .padding(.bottom, 4)
                .disabled(input.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            .padding()
            .background(Color(NSColor.windowBackgroundColor))
        }
    }
    
    private func sendMessage() {
        let text = input
        input = ""
        appState.send(text)
    }
}
