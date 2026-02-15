//
// PURPOSE:
// This Swift component is part of the SentinelForge macOS UI.
// [Specific purpose based on component name: DashboardView]
//
// KEY RESPONSIBILITIES:
// - [Automatically generated - review and enhance based on actual functionality]
//
// INTEGRATION:
// - Used by: [To be documented]
// - Depends on: [To be documented]
//

import SwiftUI

/// Struct DashboardView.
struct DashboardView: View {
    @EnvironmentObject var appState: HelixAppState
    @StateObject var backend = BackendManager.shared

    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                // Connection status
                ConnectionStatusBanner()

                if let p0 = appState.activeP0Alert {
                    P0AlertBanner(alert: p0) { appState.activeP0Alert = nil }
                }
                if let waf = appState.wafStatus {
                    WAFStatusBanner(waf: waf) { appState.wafStatus = nil }
                }

                // Status Cards Row
                HStack(spacing: 16) {
                    // Backend Status
                    SystemStatusCard(
                        title: "Backend",
                        isConnected: backend.isRunning,
                        statusText: backend.status,
                        icon: "server.rack"
                    )

                    // AI Status
                    SystemStatusCard(
                        title: "AI Engine",
                        isConnected: appState.aiStatus?.connected ?? false,
                        statusText: appState.aiStatus?.model ?? "Offline",
                        icon: "cpu"
                    )

                    // Ghost Protocol
                    Button(action: { appState.toggleGhost() }) {
                        SystemStatusCard(
                            title: "Ghost Protocol",
                            isConnected: appState.isGhostActive,
                            statusText: appState.isGhostActive
                                ? (appState.ghostPort.map { "Active (\($0))" } ?? "Active")
                                : "Inactive",
                            icon: "eye"
                        )
                    }
                    .buttonStyle(.plain)
                }
                .padding(.horizontal)

                // Top Stats Row
                HStack(spacing: 20) {
                    StatCard(
                        title: "Risk Score",
                        value: calculateRisk(),
                        icon: "exclamationmark.shield",
                        color: riskColor(),
                        isLoading: !backend.isRunning
                    )

                    StatCard(
                        title: "Findings",
                        value: "\(appState.apiResults?.summary?.counts?.findings ?? 0)",
                        icon: "magnifyingglass",
                        color: .blue,
                        isLoading: !backend.isRunning
                    )

                    StatCard(
                        title: "Active Tasks",
                        value: appState.engineStatus?.scanRunning == true ? "Running" : "Idle",
                        icon: "cpu",
                        color: appState.engineStatus?.scanRunning == true ? .green : .gray,
                        isLoading: !backend.isRunning,
                        showProgress: appState.engineStatus?.scanRunning == true
                    )
                }
                .padding(.horizontal)

                // Critical Issues
                VStack(alignment: .leading) {
                    Text("Critical Issues")
                        .font(.headline)
                        .padding(.horizontal)

                    if let issues = appState.apiResults?.issues, !issues.isEmpty {
                        ForEach(issues.prefix(5).indices, id: \.self) { idx in
                            let issue = issues[idx]
                            IssueRow(issue: issue)
                        }
                    } else {
                        Text("No critical issues detected yet.")
                            .foregroundColor(.secondary)
                            .padding()
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color(NSColor.controlBackgroundColor))
                            .cornerRadius(8)
                            .padding(.horizontal)
                    }
                }

                // Decision Stream (New)
                DecisionStreamView(decisions: appState.decisions)
                    .padding(.horizontal)

                // Tool Health
                VStack(alignment: .leading) {
                    Text("System Status")
                        .font(.headline)
                        .padding(.horizontal)

                    // Conditional branch.
                    if let tools = appState.engineStatus?.tools {
                        HStack {
                            VStack(alignment: .leading) {
                                Text("Tools Installed")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                                Text("\(tools.countInstalled) / \(tools.countTotal)")
                                    .font(.title2)
                                    .bold()
                            }
                            Spacer()
                            // Conditional branch.
                            if !tools.missing.isEmpty {
                                VStack(alignment: .trailing) {
                                    Text("Missing Tools")
                                        .font(.caption)
                                        .foregroundColor(.orange)
                                    ForEach(tools.missing.prefix(3), id: \.self) { tool in
                                        Text(tool)
                                            .font(.caption2)
                                            .foregroundColor(.secondary)
                                    }
                                }
                            } else {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundColor(.green)
                                    .font(.title)
                            }
                        }
                        .padding()
                        .background(Color(NSColor.controlBackgroundColor))
                        .cornerRadius(8)
                        .padding(.horizontal)
                    }
                }
            }
            .padding(.vertical)
        }
    }

    /// Function calculateRisk.
    func calculateRisk() -> String {
        // Placeholder for real risk score from Python
        let issues = appState.apiResults?.issues ?? []
        let criticals = issues.filter { $0["severity"]?.stringValue == "CRITICAL" }.count
        let highs = issues.filter { $0["severity"]?.stringValue == "HIGH" }.count

        let score = (criticals * 10) + (highs * 5)
        return "\(score)"
    }

    /// Function riskColor.
    func riskColor() -> Color {
        let score = Int(calculateRisk()) ?? 0
        // Conditional branch.
        if score > 50 { return .red }
        // Conditional branch.
        if score > 20 { return .orange }
        return .green
    }
}

/// Struct StatCard.
struct StatCard: View {
    let title: String
    let value: String
    let icon: String
    let color: Color
    var isLoading: Bool = false
    var showProgress: Bool = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: icon)
                    .foregroundColor(color)
                    .font(.title2)
                Spacer()
                // Conditional branch.
                if showProgress {
                    ProgressView()
                        .scaleEffect(0.7)
                }
            }

            // Conditional branch.
            if isLoading {
                HStack(spacing: 8) {
                    ProgressView()
                        .scaleEffect(0.8)
                    Text("Loading...")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            } else {
                Text(value)
                    .font(.system(size: 28, weight: .bold))
                    .textSelection(.enabled)
            }

            // Conditional branch.
            if showProgress {
                IndeterminateProgressBar(color: color)
            }

            Text(title)
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .padding()
        .frame(maxWidth: .infinity)
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(12)
        .shadow(color: Color.black.opacity(0.1), radius: 2, x: 0, y: 1)
    }
}

// MARK: - System Status Card
/// Struct SystemStatusCard.
struct SystemStatusCard: View {
    let title: String
    let isConnected: Bool
    let statusText: String
    let icon: String

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .font(.title2)
                .foregroundColor(isConnected ? .green : .orange)

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.caption)
                    .foregroundColor(.secondary)

                HStack(spacing: 4) {
                    // Conditional branch.
                    if !isConnected {
                        ProgressView()
                            .scaleEffect(0.6)
                    } else {
                        Circle()
                            .fill(Color.green)
                            .frame(width: 6, height: 6)
                    }
                    Text(statusText)
                        .font(.caption)
                        .fontWeight(.medium)
                        .lineLimit(1)
                }
            }

            Spacer()
        }
        .padding()
        .frame(maxWidth: .infinity)
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(8)
    }
}

/// Struct IssueRow.
struct IssueRow: View {
    let issue: JSONDict

    var body: some View {
        HStack {
            let severity = issue["severity"]?.stringValue ?? "INFO"
            Circle()
                .fill(severityColor(severity))
                .frame(width: 8, height: 8)

            VStack(alignment: .leading) {
                Text(issue["title"]?.stringValue ?? "Unknown Issue")
                    .font(.body)
                    .bold()
                Text(issue["target"]?.stringValue ?? "Unknown Target")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            Spacer()
            Text(severity)
                .font(.caption)
                .padding(4)
                .background(severityColor(severity).opacity(0.2))
                .cornerRadius(4)
        }
        .padding()
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(8)
        .padding(.horizontal)
        .textSelection(.enabled)
    }

    /// Function severityColor.
    func severityColor(_ sev: String) -> Color {
        // Switch over value.
        switch sev {
        case "P0", "CRITICAL_SOURCE_EXPOSURE": return .red
        case "CRITICAL": return .purple
        case "HIGH": return .red
        case "MEDIUM": return .orange
        case "LOW": return .yellow
        default: return .blue
        }
    }
}
