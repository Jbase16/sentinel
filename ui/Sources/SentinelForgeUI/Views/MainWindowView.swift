import SwiftUI

// Simple chat-oriented shell for early Sentinel UI.
// This adds minimal scan controls and a basic log/result viewer so we can
// exercise the Python bridge while we flesh out the UI.
struct MainWindowView: View {

    @EnvironmentObject var appState: HelixAppState
    @State private var input: String = ""
    @State private var scanTarget: String = ""

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            scanControls
            Divider()
            transcript
            Divider()
            logsAndResults
            Divider()
            inputArea
        }
        .frame(minWidth: 700, minHeight: 480)
    }

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text("Sentinel")
                    .font(.title2)
                    .bold()
                Text(appState.thread.title)
                    .font(.subheadline)
                    .foregroundColor(.secondary)
            }

            Spacer()

            if appState.isProcessing {
                HStack(spacing: 8) {
                    ProgressView()
                        .scaleEffect(0.7)
                    Button("Stop") {
                        appState.cancelGeneration()
                    }
                    .keyboardShortcut(.escape, modifiers: [])
                }
            }
        }
        .padding()
    }

    // Kick off scans, poll logs/results, and show quick actions.
    private var scanControls: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Scan Control")
                .font(.headline)
            HStack {
                TextField("Target (e.g., https://example.com)", text: $scanTarget)
                    .textFieldStyle(.roundedBorder)
                Button("Start Scan") {
                    appState.startScan(target: scanTarget)
                }
                .disabled(scanTarget.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
            HStack {
                Button("Refresh Logs") {
                    appState.refreshLogs()
                }
                Button("Refresh Results") {
                    appState.refreshResults()
                }
                Spacer()
            }
        }
        .padding([.leading, .trailing, .bottom])
    }

    private var transcript: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 8) {
                    ForEach(appState.thread.messages) { msg in
                            ChatBubbleView(message: msg)
                                .id(msg.id)
                    }
                }
                .padding()
            }
            .background(Color(NSColor.textBackgroundColor))
            .onChange(of: appState.thread.messages.count) {
                if let last = appState.thread.messages.last {
                    withAnimation {
                        proxy.scrollTo(last.id, anchor: .bottom)
                    }
                }
            }
        }
    }

    // Minimal log viewer and a tiny summary of results.
    private var logsAndResults: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Engine Logs")
                .font(.headline)
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 4) {
                    ForEach(appState.apiLogs, id: \.self) { line in
                        Text(line)
                            .font(.system(size: 12, design: .monospaced))
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                .padding(6)
            }
            .frame(maxHeight: 120)
            .background(Color(NSColor.textBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 6))

            if let results = appState.apiResults {
                Text("Latest Results")
                    .font(.headline)
                VStack(alignment: .leading, spacing: 4) {
                    Text("Target: \(results.target)")
                    Text("Findings: \(results.findings?.count ?? 0)")
                    Text("Issues: \(results.issues?.count ?? 0)")
                    Text("Killchain edges: \(results.killchain_edges?.count ?? 0)")
                }
                .font(.subheadline)

                if let findings = results.findings, !findings.isEmpty {
                    Text("Findings (sample)")
                        .font(.subheadline)
                        .padding(.top, 4)
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(Array(findings.prefix(5)).enumerated().map({ $0 }), id: \.offset) { _, item in
                            let type = item["type"]?.stringValue ?? "Unknown"
                            let severity = item["severity"]?.stringValue ?? "?"
                            let tool = item["tool"]?.stringValue ?? "tool"
                            Text("[\(severity)] \(type) (\(tool))")
                                .font(.system(size: 12, design: .monospaced))
                        }
                    }
                }
            }
        }
        .padding([.leading, .trailing, .bottom])
    }

    private var inputArea: some View {
        HStack(alignment: .bottom, spacing: 8) {
            TextEditor(text: $input)
                .font(.body)
                .frame(minHeight: 40, maxHeight: 120)
                .clipShape(RoundedRectangle(cornerRadius: 8))
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(Color.gray.opacity(0.3))
                )

            VStack(spacing: 8) {
                Button {
                    send()
                } label: {
                    Text(appState.isProcessing ? "Sending…" : "Send")
                        .frame(minWidth: 70)
                }
                .keyboardShortcut(.return, modifiers: [.command])
                .disabled(input.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || appState.isProcessing)

                Button("Clear") {
                    appState.clear()
                }
                .disabled(appState.thread.messages.isEmpty)
            }
        }
        .padding()
    }

    private func send() {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        appState.send(trimmed)
        input = ""
    }
}

struct MainWindowView_Previews: PreviewProvider {
    static var previews: some View {
        MainActor.assumeIsolated {
            MainWindowView()
                .environmentObject(HelixAppState())
                .frame(width: 900, height: 600)
        }
    }
}
