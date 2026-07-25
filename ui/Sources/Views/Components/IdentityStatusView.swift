//
//  IdentityStatusView.swift
//  SentinelForgeUI
//
//  Visualizes the current Doppelganger identity state.
//

import SwiftUI

struct IdentityStatusView: View {
    @ObservedObject var appState: HelixAppState

    var body: some View {
        HStack(spacing: 12) {
            if let identity = appState.currentIdentity {
                // Authenticated State
                HStack(spacing: 8) {
                    Image(systemName: "person.fill.checkmark")
                        .foregroundColor(.green)

                    VStack(alignment: .leading, spacing: 2) {
                        Text(identity)
                            .font(.caption)
                            .fontWeight(.bold)
                            .foregroundColor(.primary)

                        if let role = appState.currentRole {
                            Text(role)
                                .font(.caption2)
                                .foregroundColor(.secondary)
                        }
                    }
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 6)
                .background(Color.green.opacity(0.1))
                .cornerRadius(8)
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(Color.green.opacity(0.3), lineWidth: 1)
                )
            } else {
                // Anonymous State
                HStack(spacing: 6) {
                    Image(systemName: "person.slash")
                        .foregroundColor(.secondary)
                    Text("Anonymous")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 6)
                .opacity(0.7)
            }
        }
    }
}
