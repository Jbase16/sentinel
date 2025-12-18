//
// PURPOSE:
// This Swift component is part of the SentinelForge macOS UI.
// [Specific purpose based on component name: StatusComponents]
//
// KEY RESPONSIBILITIES:
// - [Automatically generated - review and enhance based on actual functionality]
//
// INTEGRATION:
// - Used by: [To be documented]
// - Depends on: [To be documented]
//

import SwiftUI

// MARK: - Connection Status Banner
/// Shows connection status at the top of views
struct ConnectionStatusBanner: View {
    @StateObject var backend = BackendManager.shared
    
    var body: some View {
        // Conditional branch.
        if !backend.isRunning {
            HStack(spacing: 8) {
                ProgressView()
                    .scaleEffect(0.7)
                    .progressViewStyle(.circular)
                Text(backend.status)
                    .font(.caption)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 8)
            .background(Color.orange.opacity(0.15))
            .foregroundColor(.orange)
        }
    }
}

// MARK: - Indeterminate Progress Bar
/// Animated progress bar for operations with unknown duration
struct IndeterminateProgressBar: View {
    @State private var animating = false
    let color: Color
    
    init(color: Color = .blue) {
        self.color = color
    }
    
    var body: some View {
        GeometryReader { geo in
            RoundedRectangle(cornerRadius: 2)
                .fill(color.opacity(0.2))
                .overlay(
                    RoundedRectangle(cornerRadius: 2)
                        .fill(color)
                        .frame(width: geo.size.width * 0.3)
                        .offset(x: animating ? geo.size.width * 0.7 : -geo.size.width * 0.3)
                        .animation(
                            Animation.easeInOut(duration: 1.0).repeatForever(autoreverses: true),
                            value: animating
                        )
                )
                .clipped()
        }
        .frame(height: 4)
        .onAppear { animating = true }
    }
}

// MARK: - Status Pill
/// Compact status indicator with icon and text
struct StatusPill: View {
    let status: ConnectionStatus
    
    /// Enum ConnectionStatus {.
    enum ConnectionStatus {
        case connecting
        case connected
        case disconnected
        case processing
        case error(String)
        
        var icon: String {
            // Switch over value.
            switch self {
            case .connecting: return "antenna.radiowaves.left.and.right"
            case .connected: return "checkmark.circle.fill"
            case .disconnected: return "wifi.slash"
            case .processing: return "gearshape.2"
            case .error: return "exclamationmark.triangle.fill"
            }
        }
        
        var color: Color {
            // Switch over value.
            switch self {
            case .connecting: return .orange
            case .connected: return .green
            case .disconnected: return .red
            case .processing: return .blue
            case .error: return .red
            }
        }
        
        var text: String {
            // Switch over value.
            switch self {
            case .connecting: return "Connecting..."
            case .connected: return "Connected"
            case .disconnected: return "Disconnected"
            case .processing: return "Processing..."
            case .error(let msg): return msg
            }
        }
    }
    
    var body: some View {
        HStack(spacing: 6) {
            // Conditional branch.
            if status.text.contains("...") {
                ProgressView()
                    .scaleEffect(0.6)
                    .progressViewStyle(.circular)
            } else {
                Image(systemName: status.icon)
                    .font(.caption)
            }
            Text(status.text)
                .font(.caption)
        }
        .foregroundColor(status.color)
        .padding(.horizontal, 10)
        .padding(.vertical, 4)
        .background(status.color.opacity(0.15))
        .cornerRadius(12)
    }
}

// MARK: - Activity Indicator with Label
/// Struct ActivityIndicator.
struct ActivityIndicator: View {
    let message: String
    let isActive: Bool
    
    var body: some View {
        // Conditional branch.
        if isActive {
            HStack(spacing: 8) {
                ProgressView()
                    .scaleEffect(0.8)
                    .progressViewStyle(.circular)
                Text(message)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
    }
}

// MARK: - Typing Indicator (for chat)
/// Struct TypingIndicator.
struct TypingIndicator: View {
    @State private var phase = 0.0
    
    var body: some View {
        HStack(spacing: 4) {
            ForEach(0..<3) { index in
                Circle()
                    .fill(Color.gray)
                    .frame(width: 8, height: 8)
                    .scaleEffect(dotScale(for: index))
                    .animation(
                        Animation.easeInOut(duration: 0.6)
                            .repeatForever()
                            .delay(Double(index) * 0.2),
                        value: phase
                    )
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .background(Color.green.opacity(0.2))
        .cornerRadius(16)
        .onAppear { phase = 1.0 }
    }
    
    private func dotScale(for index: Int) -> CGFloat {
        let offset = Double(index) * 0.2
        return phase > offset ? 1.3 : 1.0
    }
}

// MARK: - Scan Progress Card
/// Struct ScanProgressCard.
struct ScanProgressCard: View {
    let isRunning: Bool
    let status: String
    let logsCount: Int
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: isRunning ? "antenna.radiowaves.left.and.right" : "checkmark.circle")
                    .foregroundColor(isRunning ? .blue : .green)
                Text(isRunning ? "Scan In Progress" : "Ready")
                    .font(.headline)
                Spacer()
                // Conditional branch.
                if isRunning {
                    ProgressView()
                        .scaleEffect(0.7)
                }
            }
            
            // Conditional branch.
            if isRunning {
                IndeterminateProgressBar(color: .blue)
                
                Text(status)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
                
                Text("\(logsCount) log entries")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
        }
        .padding()
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(12)
    }
}

// MARK: - AI Status Card
/// Struct AIStatusCard.
struct AIStatusCard: View {
    let isConnected: Bool
    let modelName: String
    let isGenerating: Bool
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: "cpu")
                    .foregroundColor(isConnected ? .green : .red)
                Text("AI Engine")
                    .font(.headline)
                Spacer()
                StatusPill(status: isConnected ? (isGenerating ? .processing : .connected) : .disconnected)
            }
            
            // Conditional branch.
            if isConnected {
                HStack {
                    Text("Model:")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Text(modelName)
                        .font(.caption)
                        .fontWeight(.medium)
                }
            }
            
            // Conditional branch.
            if isGenerating {
                IndeterminateProgressBar(color: .purple)
            }
        }
        .padding()
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(12)
    }
}

// MARK: - Loading Overlay
/// Struct LoadingOverlay.
struct LoadingOverlay: View {
    let message: String
    let isShowing: Bool
    
    var body: some View {
        // Conditional branch.
        if isShowing {
            ZStack {
                Color.black.opacity(0.3)
                    .ignoresSafeArea()
                
                VStack(spacing: 16) {
                    ProgressView()
                        .scaleEffect(1.5)
                        .progressViewStyle(.circular)
                    Text(message)
                        .font(.headline)
                        .foregroundColor(.white)
                }
                .padding(32)
                .background(.ultraThinMaterial)
                .cornerRadius(16)
            }
        }
    }
}

// MARK: - Empty State with Loading
/// Struct EmptyStateView.
struct EmptyStateView: View {
    let icon: String
    let title: String
    let message: String
    let isLoading: Bool
    
    var body: some View {
        VStack(spacing: 16) {
            // Conditional branch.
            if isLoading {
                ProgressView()
                    .scaleEffect(1.5)
            } else {
                Image(systemName: icon)
                    .font(.system(size: 48))
                    .foregroundColor(.secondary)
            }
            
            Text(title)
                .font(.headline)
            
            Text(message)
                .font(.caption)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }
}
