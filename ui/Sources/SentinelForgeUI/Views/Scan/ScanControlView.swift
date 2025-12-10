import SwiftUI

struct ScanControlView: View {
    @EnvironmentObject var appState: HelixAppState
    @State private var scanTarget: String = ""
    
    var body: some View {
        VStack(spacing: 0) {
            // Permission Requests
            ActionRequestView()
            
            // Header / Input
            HStack {
                TextField("Target (e.g., https://example.com)", text: $scanTarget)
                    .textFieldStyle(.roundedBorder)
                    .font(.body)
                
                if appState.engineStatus?.scanRunning == true {
                    Button(action: { appState.cancelScan() }) {
                        Label("Stop", systemImage: "stop.fill")
                    }
                    .tint(.red)
                } else {
                    Button(action: { appState.startScan(target: scanTarget) }) {
                        Label("Start Scan", systemImage: "play.fill")
                    }
                    .disabled(scanTarget.isEmpty)
                }
            }
            .padding()
            .background(Color(NSColor.windowBackgroundColor))
            
            Divider()
            
            // Two-pane layout: Findings List | Logs
            GeometryReader { geo in
                HSplitView {
                    FindingsListView()
                        .frame(minWidth: 300)
                    
                    LogConsoleView()
                        .frame(minWidth: 300)
                }
            }
        }
    }
}

struct FindingsListView: View {
    @EnvironmentObject var appState: HelixAppState
    
    var body: some View {
        List {
            Section(header: Text("Findings")) {
                if let findings = appState.apiResults?.findings {
                    ForEach(findings.indices, id: \.self) { idx in
                        let f = findings[idx]
                        FindingRow(finding: f)
                    }
                } else {
                    Text("No findings yet.")
                        .foregroundColor(.secondary)
                }
            }
        }
    }
}

struct FindingRow: View {
    let finding: JSONDict
    
    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                Text(finding["type"]?.stringValue ?? "Unknown")
                    .font(.headline)
                Spacer()
                Text(finding["tool"]?.stringValue ?? "")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            Text(finding["message"]?.stringValue ?? "")
                .font(.caption)
                .lineLimit(2)
        }
        .padding(.vertical, 4)
    }
}

struct LogConsoleView: View {
    @EnvironmentObject var appState: HelixAppState
    
    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                Text("Live Logs")
                    .font(.caption)
                    .bold()
                Spacer()
                Button("Clear") {
                    // appState.clearLogs() // To be implemented
                }
                .buttonStyle(.plain)
                .font(.caption)
            }
            .padding(8)
            .background(Color(NSColor.controlBackgroundColor))
            
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 2) {
                    ForEach(appState.apiLogs, id: \.self) { line in
                        Text(line)
                            .font(.system(size: 11, design: .monospaced))
                            .textSelection(.enabled)
                    }
                }
                .padding(8)
            }
        }
        .background(Color.black)
    }
}
