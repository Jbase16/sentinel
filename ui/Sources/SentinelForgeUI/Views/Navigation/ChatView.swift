import SwiftUI

struct ChatView: View {
    @EnvironmentObject var appState: HelixAppState
    @State private var input: String = ""
    @FocusState private var isFocused: Bool
    
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
            // Close keyboard on scroll (optional, mostly mobile behavior but good practice)
            .onTapGesture {
                isFocused = false
            }
            
            Divider()
            
            HStack(alignment: .bottom) {
                TextField("Message Sentinel AI...", text: $input)
                    .textFieldStyle(.roundedBorder)
                    .focused($isFocused)
                    .onSubmit {
                        sendMessage()
                    }
                    .frame(minHeight: 30)
                
                Button(action: sendMessage) {
                    Image(systemName: "paperplane.fill")
                        .font(.title2)
                        .foregroundColor(.blue)
                }
                .buttonStyle(.plain)
                .padding(.bottom, 2) // Minor alignment tweak
                .disabled(input.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            .padding()
            .background(Color(NSColor.windowBackgroundColor))
        }
        .onAppear {
            isFocused = true
        }
    }
    
    private func sendMessage() {
        let text = input
        input = ""
        appState.send(text)
    }
}
