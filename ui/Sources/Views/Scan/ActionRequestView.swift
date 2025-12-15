// ============================================================================
// ui/Sources/Views/Scan/ActionRequestView.swift
// Actionrequestview Component
// ============================================================================
//
// PURPOSE:
// This Swift component is part of the SentinelForge macOS UI.
// [Specific purpose based on component name: ActionRequestView]
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

struct ActionRequestView: View {
    @EnvironmentObject var appState: HelixAppState
    
    var body: some View {
        if !appState.pendingActions.isEmpty {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Image(systemName: "hand.raised.fill")
                        .foregroundColor(.orange)
                    Text("Permission Required")
                        .font(.headline)
                    Spacer()
                    Text("\(appState.pendingActions.count)")
                        .font(.caption)
                        .padding(5)
                        .background(Color.orange.opacity(0.2))
                        .cornerRadius(5)
                }
                
                ScrollView(.horizontal) {
                    HStack(spacing: 12) {
                        ForEach(appState.pendingActions) { action in
                            ActionCard(action: action)
                        }
                    }
                }
            }
            .padding()
            .background(Color(NSColor.windowBackgroundColor))
            .cornerRadius(12)
            .overlay(
                RoundedRectangle(cornerRadius: 12)
                    .stroke(Color.orange.opacity(0.5), lineWidth: 1)
            )
            .shadow(color: Color.black.opacity(0.1), radius: 4, x: 0, y: 2)
            .padding()
            .transition(.move(edge: .top).combined(with: .opacity))
        }
    }
}

struct ActionCard: View {
    @EnvironmentObject var appState: HelixAppState
    let action: PendingAction
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(action.tool.uppercased())
                    .font(.caption)
                    .bold()
                    .padding(4)
                    .background(Color.blue.opacity(0.2))
                    .cornerRadius(4)
                
                Spacer()
                
                Text(action.timestamp ?? "")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
            
            Text(action.reason ?? "No reason provided")
                .font(.body)
                .lineLimit(3)
                .frame(height: 60, alignment: .topLeading)
            
            Text("Target: \(action.target ?? "Unknown")")
                .font(.caption)
                .foregroundColor(.secondary)
            
            HStack {
                Button(action: { appState.denyAction(action) }) {
                    Label("Deny", systemImage: "xmark")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .tint(.red)
                
                Button(action: { appState.approveAction(action) }) {
                    Label("Approve", systemImage: "checkmark")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .tint(.green)
            }
        }
        .padding()
        .frame(width: 280)
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(8)
    }
}
