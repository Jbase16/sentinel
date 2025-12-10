import SwiftUI

struct DashboardView: View {
    @EnvironmentObject var appState: HelixAppState
    
    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                // Top Stats Row
                HStack(spacing: 20) {
                    StatCard(
                        title: "Risk Score",
                        value: calculateRisk(),
                        icon: "exclamationmark.shield",
                        color: riskColor()
                    )
                    
                    StatCard(
                        title: "Findings",
                        value: "\(appState.apiResults?.summary?.counts?.findings ?? 0)",
                        icon: "magnifyingglass",
                        color: .blue
                    )
                    
                    StatCard(
                        title: "Active Tasks",
                        value: appState.engineStatus?.scanRunning == true ? "Running" : "Idle",
                        icon: "cpu",
                        color: appState.engineStatus?.scanRunning == true ? .green : .gray
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
                
                // Tool Health
                VStack(alignment: .leading) {
                    Text("System Status")
                        .font(.headline)
                        .padding(.horizontal)
                    
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
    
    func calculateRisk() -> String {
        // Placeholder for real risk score from Python
        let issues = appState.apiResults?.issues ?? []
        let criticals = issues.filter { $0["severity"]?.stringValue == "CRITICAL" }.count
        let highs = issues.filter { $0["severity"]?.stringValue == "HIGH" }.count
        
        let score = (criticals * 10) + (highs * 5)
        return "\(score)"
    }
    
    func riskColor() -> Color {
        let score = Int(calculateRisk()) ?? 0
        if score > 50 { return .red }
        if score > 20 { return .orange }
        return .green
    }
}

struct StatCard: View {
    let title: String
    let value: String
    let icon: String
    let color: Color
    
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: icon)
                    .foregroundColor(color)
                    .font(.title2)
                Spacer()
            }
            
            Text(value)
                .font(.system(size: 28, weight: .bold))
            
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
    }
    
    func severityColor(_ sev: String) -> Color {
        switch sev {
        case "CRITICAL": return .purple
        case "HIGH": return .red
        case "MEDIUM": return .orange
        case "LOW": return .yellow
        default: return .blue
        }
    }
}
