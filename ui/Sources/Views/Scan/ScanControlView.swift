import SwiftUI

struct ScanControlView: View {
    @EnvironmentObject var appState: HelixAppState
    @StateObject var backend = BackendManager.shared
    @State private var scanTarget: String = "http://testphp.vulnweb.com"
    @FocusState private var isFocused: Bool

    private var isScanning: Bool {
        appState.engineStatus?.scanRunning == true || appState.isScanRunning
    }

    var body: some View {
        VStack(spacing: 0) {
            // Connection status
            ConnectionStatusBanner()

            // Permission Requests
            ActionRequestView()

            // Scan Progress Header
            if isScanning {
                ScanProgressHeader(logCount: appState.apiLogItems.count)
            }

            // Header / Input
            HStack {
                TextField("Target (e.g., https://example.com)", text: $scanTarget)
                    .textFieldStyle(.roundedBorder)
                    .font(.body)
                    .focused($isFocused)
                    .onSubmit {
                        if !scanTarget.isEmpty && backend.isRunning {
                            appState.startScan(target: scanTarget)
                        }
                    }
                    .disabled(!backend.isRunning || isScanning)

                if isScanning {
                    Button(action: { appState.cancelScan() }) {
                        HStack(spacing: 4) {
                            ProgressView()
                                .scaleEffect(0.6)
                            Text("Stop")
                        }
                    }
                    .tint(.red)
                } else {
                    Button(action: { appState.startScan(target: scanTarget) }) {
                        Label("Start Scan", systemImage: "play.fill")
                    }
                    .disabled(scanTarget.isEmpty || !backend.isRunning)
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

// MARK: - Scan Progress Header
struct ScanProgressHeader: View {
    let logCount: Int
    @State private var elapsedTime: Int = 0
    @State private var timer: Timer?

    var body: some View {
        VStack(spacing: 8) {
            HStack {
                Image(systemName: "antenna.radiowaves.left.and.right")
                    .foregroundColor(.blue)
                Text("Scan In Progress")
                    .font(.headline)
                Spacer()
                Text(formattedTime)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .monospacedDigit()
            }

            IndeterminateProgressBar(color: .blue)

            HStack {
                Text("\(logCount) log entries")
                    .font(.caption2)
                    .foregroundColor(.secondary)
                Spacer()
                ProgressView()
                    .scaleEffect(0.6)
            }
        }
        .padding()
        .background(Color.blue.opacity(0.1))
        .onAppear {
            timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in
                elapsedTime += 1
            }
        }
        .onDisappear {
            timer?.invalidate()
        }
    }

    private var formattedTime: String {
        let mins = elapsedTime / 60
        let secs = elapsedTime % 60
        return String(format: "%02d:%02d", mins, secs)
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
        .textSelection(.enabled)
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
                    ForEach(appState.apiLogItems) { item in
                        Text(item.text)
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
