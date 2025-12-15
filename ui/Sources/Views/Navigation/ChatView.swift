// ============================================================================
// ui/Sources/Views/Navigation/ChatView.swift
// Chatview Component
// ============================================================================
//
// PURPOSE:
// This Swift component is part of the SentinelForge macOS UI.
// [Specific purpose based on component name: ChatView]
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

struct ChatView: View {
    @EnvironmentObject var appState: HelixAppState
    @StateObject var backend = BackendManager.shared
    @State private var input: String = ""
    @FocusState private var isFocused: Bool
    
    var body: some View {
        VStack(spacing: 0) {
            // Connection status banner
            ConnectionStatusBanner()
            
            // AI Status header
            AIStatusHeader()
            
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 12) {
                        ForEach(appState.thread.messages) { msg in
                            ChatBubbleView(message: msg, isStreaming: appState.isProcessing && msg == appState.thread.messages.last && msg.role == .assistant)
                                .id(msg.id)
                        }
                        
                        // Show typing indicator when processing
                        if appState.isProcessing && (appState.thread.messages.last?.text.isEmpty ?? true) {
                            HStack {
                                Spacer()
                                TypingIndicator()
                            }
                        }
                    }
                    .padding()
                }
                .onChange(of: appState.thread.messages.count) {
                    if let last = appState.thread.messages.last {
                        withAnimation {
                            proxy.scrollTo(last.id, anchor: .bottom)
                        }
                    }
                }
                .onChange(of: appState.thread.messages.last?.text) {
                    // Auto-scroll as new tokens arrive
                    if let last = appState.thread.messages.last {
                        proxy.scrollTo(last.id, anchor: .bottom)
                    }
                }
            }
            
            Divider()
            
            // Input area with processing indicator
            VStack(spacing: 8) {
                if appState.isProcessing {
                    IndeterminateProgressBar(color: .blue)
                }
                
                HStack(alignment: .bottom) {
                    TextField("Message Sentinel AI...", text: $input)
                        .textFieldStyle(.roundedBorder)
                        .focused($isFocused)
                        .onSubmit {
                            sendMessage()
                        }
                        .frame(minHeight: 30)
                        .disabled(!backend.isRunning || appState.isProcessing)
                    
                    Button(action: sendMessage) {
                        if appState.isProcessing {
                            ProgressView()
                                .scaleEffect(0.8)
                                .frame(width: 24, height: 24)
                        } else {
                            Image(systemName: "paperplane.fill")
                                .font(.title2)
                                .foregroundColor(backend.isRunning ? .blue : .gray)
                        }
                    }
                    .buttonStyle(.plain)
                    .padding(.bottom, 2)
                    .disabled(input.trimmingCharacters(in: .whitespaces).isEmpty || !backend.isRunning || appState.isProcessing)
                }
            }
            .padding()
            .background(Color(NSColor.windowBackgroundColor))
        }
        .onAppear {
            isFocused = true
        }
    }
    
    private func sendMessage() {
        guard backend.isRunning else { return }
        let text = input
        input = ""
        appState.send(text)
    }
}

// MARK: - AI Status Header
struct AIStatusHeader: View {
    @EnvironmentObject var appState: HelixAppState
    @StateObject var backend = BackendManager.shared
    
    var body: some View {
        HStack {
            Image(systemName: "cpu")
                .foregroundColor(aiConnected ? .green : .orange)
            
            Text(modelName)
                .font(.caption)
                .fontWeight(.medium)
            
            Spacer()
            
            StatusPill(status: currentStatus)
        }
        .padding(.horizontal)
        .padding(.vertical, 8)
        .background(Color(NSColor.controlBackgroundColor).opacity(0.5))
    }
    
    private var aiConnected: Bool {
        appState.aiStatus?.connected ?? false
    }
    
    private var modelName: String {
        appState.aiStatus?.model ?? "No Model"
    }
    
    private var currentStatus: StatusPill.ConnectionStatus {
        if !backend.isRunning {
            return .connecting
        } else if !aiConnected {
            return .error("AI Offline")
        } else if appState.isProcessing {
            return .processing
        } else {
            return .connected
        }
    }
}
