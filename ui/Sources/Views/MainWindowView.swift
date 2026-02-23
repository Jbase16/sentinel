//
// PURPOSE:
// This Swift component is part of the SentinelForge macOS UI.
// [Specific purpose based on component name: MainWindowView]
//
// KEY RESPONSIBILITIES:
// - [Automatically generated - review and enhance based on actual functionality]
//
// INTEGRATION:
// - Used by: [To be documented]
// - Depends on: [To be documented]
//

import SwiftUI

/// Struct MainWindowView.
struct MainWindowView: View {
    @EnvironmentObject var appState: HelixAppState
    @State private var selection: SidebarItem? = .chat  // Default to Chat for usability

    /// Enum SidebarItem.
    enum SidebarItem: String, Identifiable, CaseIterable {
        case dashboard = "Dashboard"
        case scan = "Target Scan"
        case graph = "Attack Graph"
        case terminal = "System Console"
        case report = "Report Composer"
        case tools = "Tool Bank"
        case audit = "Audit Feed"
        case chat = "AI Assistant"

        var id: String { rawValue }
        var icon: String {
            // Switch over value.
            switch self {
            case .dashboard: return "gauge"
            case .scan: return "dot.scope"
            case .graph: return "network"
            case .terminal: return "command.square.fill"
            case .report: return "doc.text.fill"
            case .tools: return "wrench.and.screwdriver.fill"
            case .audit: return "list.bullet.rectangle.portrait.fill"
            case .chat: return "bubble.left.and.bubble.right.fill"
            }
        }
    }

    var body: some View {
        ZStack {
            // Background: Deep Space / Cyberpunk
            Color(red: 0.05, green: 0.05, blue: 0.08)
                .edgesIgnoringSafeArea(.all)

            HStack(spacing: 0) {
                // Cyberpunk Sidebar
                VStack(alignment: .leading, spacing: 12) {
                    Text("SENTINEL")
                        .font(.system(size: 20, weight: .black, design: .monospaced))
                        .foregroundColor(.cyberCyan)
                        .padding(.top, 30)
                        .padding(.leading, 20)

                    Divider().background(Color.cyberCyan.opacity(0.3))

                    ForEach(SidebarItem.allCases) { item in
                        Button(action: { selection = item }) {
                            HStack {
                                Image(systemName: item.icon)
                                    .frame(width: 24)
                                Text(item.rawValue)
                                    .font(.system(size: 13, weight: .medium, design: .monospaced))
                                Spacer()
                            }
                            .foregroundColor(selection == item ? .white : .gray)
                            .padding(.vertical, 8)
                            .padding(.horizontal, 16)
                            .background(
                                selection == item ? Color.cyberBlue.opacity(0.2) : Color.clear
                            )
                            .cornerRadius(8)
                        }
                        .buttonStyle(.plain)
                        .padding(.horizontal, 10)
                    }

                    Spacer()

                    // Status Footer
                    BackendStatusBadge()
                        .padding()
                }
                .frame(width: 240)
                .background(.ultraThinMaterial)
                .overlay(
                    Rectangle()
                        .frame(width: 1)
                        .foregroundColor(Color.white.opacity(0.1)),
                    alignment: .trailing
                )

                // Main Content Area
                VStack(spacing: 0) {
                    ZStack {
                        // Switch over value.
                        switch selection {
                        case .dashboard: DashboardView()
                        case .scan: ScanControlView()
                        case .graph: NetworkGraphView()  // Metal 3D
                        case .terminal: TerminalView()
                        case .report: ReportView()
                        case .tools: ToolsBankView()
                        case .audit: AuditFeedView()
                        case .chat: ChatView()
                        case .none: Text("Offline")
                        }
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)

                    // Time Travel Scrubber
                    SentinelTimelineView()
                }
            }
        }
        .frame(minWidth: 800, idealWidth: 1000, minHeight: 500, idealHeight: 700)
        .onAppear {
            // Only refresh status if backend is ready - prevents spamming during startup
            if BackendManager.shared.backendState == .ready {
                appState.refreshStatus()
            }
        }
    }
}

// Minimal Theme Extensions
extension Color {
    static let cyberCyan = Color(red: 0.0, green: 0.9, blue: 1.0)
    static let cyberBlue = Color(red: 0.0, green: 0.4, blue: 1.0)
}

/// Struct BackendStatusBadge.
struct BackendStatusBadge: View {
    @EnvironmentObject var appState: HelixAppState
    @StateObject var backend = BackendManager.shared
    @State private var showingSettings = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            // Backend Status
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text("BACKEND")
                        .font(.caption2)
                        .foregroundColor(.gray)

                    Spacer()

                    Button(action: { showingSettings = true }) {
                        Image(systemName: "gearshape.fill")
                            .font(.caption2)
                            .foregroundColor(.gray)
                    }
                    .buttonStyle(.plain)
                    .help("Configure backend runtime")
                }

                HStack(spacing: 6) {
                    // Conditional branch.
                    if backend.isRunning {
                        Circle()
                            .fill(Color.green)
                            .frame(width: 6, height: 6)
                            .shadow(color: .green, radius: 4)
                    } else {
                        ProgressView()
                            .scaleEffect(0.5)
                    }

                    Text(backend.status)
                        .font(.caption)
                        .foregroundColor(backend.isRunning ? .white : .orange)
                        .lineLimit(1)
                }
            }
            .padding(8)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.black.opacity(0.4))
            .cornerRadius(4)
            .sheet(isPresented: $showingSettings) {
                BackendSettingsView()
            }

            // AI Status
            VStack(alignment: .leading, spacing: 4) {
                Text("AI ENGINE")
                    .font(.caption2)
                    .foregroundColor(.gray)

                HStack(spacing: 6) {
                    let aiConnected = appState.aiStatus?.connected ?? false

                    // Conditional branch.
                    if aiConnected {
                        Circle()
                            .fill(appState.isProcessing ? Color.blue : Color.green)
                            .frame(width: 6, height: 6)
                            .shadow(color: appState.isProcessing ? .blue : .green, radius: 4)
                    } else if backend.isRunning {
                        Circle()
                            .fill(Color.orange)
                            .frame(width: 6, height: 6)
                    } else {
                        Circle()
                            .fill(Color.gray)
                            .frame(width: 6, height: 6)
                    }

                    VStack(alignment: .leading, spacing: 0) {
                        Text(appState.aiStatus?.model ?? "Waiting...")
                            .font(.caption)
                            .foregroundColor(aiConnected ? .white : .gray)
                            .lineLimit(1)

                        // Conditional branch.
                        if appState.isProcessing {
                            Text("Processing...")
                                .font(.caption2)
                                .foregroundColor(.blue)
                        }
                    }
                }

                // Show progress bar when AI is processing
                if appState.isProcessing {
                    IndeterminateProgressBar(color: .blue)
                        .padding(.top, 4)
                }
            }
            .padding(8)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.black.opacity(0.4))
            .cornerRadius(4)
        }
    }
}

// MARK: - TEMPORARY CONSOLIDATION: SentinelTimelineView
// Moved here because Xcode project target membership for 'TimeTravel/TimelineView.swift' is likely broken.

struct SentinelTimelineView: View {
    @EnvironmentObject var appState: HelixAppState

    // Local drag state for smooth scrubbing
    @State private var dragProgress: Double? = nil

    var body: some View {
        VStack(spacing: 0) {
            Divider()
                .background(Color.white.opacity(0.1))

            HStack(spacing: 16) {
                // 1. Playback Controls
                Button(action: toggleReplay) {
                    Image(
                        systemName: appState.isReplaying ? "pause.fill" : "clock.arrow.circlepath"
                    )
                    .font(.system(size: 14))
                    .foregroundColor(appState.isReplaying ? .yellow : .cyan)
                }
                .buttonStyle(.plain)
                .help(appState.isReplaying ? "Exit Replay Mode" : "Enter Time Travel")

                // 2. Scrubber
                GeometryReader { geo in
                    ZStack(alignment: .leading) {
                        // Background Track
                        Rectangle()
                            .fill(Color.white.opacity(0.1))
                            .frame(height: 4)
                            .cornerRadius(2)

                        // Progress Fill
                        let total = Double(max(1, appState.allEvents.count))
                        let current = Double(appState.replayCursor ?? appState.allEvents.count)
                        // If dragging, use dragProgress
                        let displayProgress = dragProgress ?? (current / total)

                        Rectangle()
                            .fill(appState.isReplaying ? Color.yellow : Color.cyan)
                            .frame(
                                width: geo.size.width * CGFloat(max(0, min(1, displayProgress))),
                                height: 4
                            )
                            .cornerRadius(2)

                        // Handle
                        Circle()
                            .fill(Color.white)
                            .frame(width: 12, height: 12)
                            .shadow(radius: 2)
                            .position(
                                x: geo.size.width * CGFloat(max(0, min(1, displayProgress))), y: 2)
                    }
                    .frame(height: 12)  // Touch target height
                    .gesture(
                        DragGesture()
                            .onChanged { value in
                                if !appState.isReplaying {
                                    appState.enterReplayMode()
                                }
                                let progress = max(0, min(1, value.location.x / geo.size.width))
                                dragProgress = progress

                                // Live update? Or throttle?
                                // For performance, maybe throttle updates to seek()
                                let total = Double(appState.allEvents.count)
                                let targetIndex = Int(progress * total)
                                appState.seek(to: targetIndex)
                            }
                            .onEnded { value in
                                dragProgress = nil
                                let progress = max(0, min(1, value.location.x / geo.size.width))
                                let total = Double(appState.allEvents.count)
                                let targetIndex = Int(progress * total)
                                appState.seek(to: targetIndex)
                            }
                    )
                }
                .frame(height: 12)

                // 3. Info
                Text(timestampText)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(.white.opacity(0.6))
                    .frame(width: 120, alignment: .trailing)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
            .background(Color.black.opacity(0.8))
        }
    }

    private var timestampText: String {
        if let cursor = appState.replayCursor, cursor < appState.allEvents.count {
            let event = appState.allEvents[cursor]
            // Format timestamp (assume ISO or float in event?)
            // event.timestamp is Double (UNIX)
            return formatTimestamp(event.timestamp)
        } else {
            return "LIVE"
        }
    }

    private func toggleReplay() {
        if appState.isReplaying {
            appState.exitReplayMode()
        } else {
            appState.enterReplayMode()
        }
    }

    private func formatTimestamp(_ ts: Double) -> String {
        let date = Date(timeIntervalSince1970: ts)
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss.SSS"
        return formatter.string(from: date)
    }
}
