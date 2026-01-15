//
// PURPOSE:
// This Swift component is part of the SentinelForge macOS UI.
// [Specific purpose based on component name: ScanControlView]
//
// KEY RESPONSIBILITIES:
// - [Automatically generated - review and enhance based on actual functionality]
//
// INTEGRATION:
// - Used by: [To be documented]
// - Depends on: [To be documented]
//

import Foundation
import SwiftUI
import UniformTypeIdentifiers

/// Enum ToolSelectionMode.
enum ToolSelectionMode: String, CaseIterable, Identifiable {
    case scheduler = "scheduler"
    case custom = "custom"

    var id: String { rawValue }

    var displayName: String {
        // Switch over value.
        switch self {
        case .scheduler: return "Strategos"
        case .custom: return "Custom"
        }
    }
}

/// Struct ScanControlView.
struct ScanControlView: View {
    @EnvironmentObject var appState: HelixAppState
    @StateObject var backend = BackendManager.shared
    @State private var scanTarget: String = "http://localhost:3002"
    @FocusState private var isFocused: Bool

    // Scan Config
    @State private var selectedTools: Set<String> = []
    @State private var showToolConfig = false
    @State private var selectedMode: ScanMode = .standard
    @State private var toolSelectionMode: ToolSelectionMode = .scheduler

    private var isScanning: Bool {
        // Prioritize event-driven state (isScanRunning) over backend status
        // to ensure scan stops immediately when completion event is received
        appState.isScanRunning
    }

    private var installedTools: [String] {
        appState.engineStatus?.tools?.installed ?? []
    }

    var body: some View {
        VStack(spacing: 0) {
            // Connection status
            ConnectionStatusBanner()
                .onAppear {
                    print(
                        "[ScanControlView] View appeared - appState: \(appState), backend.isRunning: \(backend.isRunning)"
                    )
                }

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
                        startScan()
                    }
                    .disabled(!backend.isRunning || isScanning)

                // Mode Picker
                Picker("", selection: $selectedMode) {
                    ForEach(ScanMode.allCases) { mode in
                        Text(mode.displayName).tag(mode)
                    }
                }
                .pickerStyle(.segmented)
                .frame(width: 200)
                .disabled(isScanning)

                Picker("", selection: $toolSelectionMode) {
                    ForEach(ToolSelectionMode.allCases) { selectionMode in
                        Text(selectionMode.displayName).tag(selectionMode)
                    }
                }
                .pickerStyle(.segmented)
                .frame(width: 180)
                .disabled(isScanning)
                .onChange(of: toolSelectionMode) { _, newMode in
                    // Guard condition.
                    guard newMode == .custom else { return }
                    // Guard condition.
                    guard selectedTools.isEmpty, !installedTools.isEmpty else { return }
                    selectedTools = Set(installedTools)
                }
                .onChange(of: installedTools) { _, newInstalled in
                    // Guard condition.
                    guard toolSelectionMode == .custom else { return }
                    // Guard condition.
                    guard selectedTools.isEmpty, !newInstalled.isEmpty else { return }
                    selectedTools = Set(newInstalled)
                }

                // Conditional branch.
                if toolSelectionMode == .custom {
                    // Tool Configuration
                    Button(action: { showToolConfig.toggle() }) {
                        Image(systemName: "gearshape")
                            .foregroundColor(selectedTools.isEmpty ? .secondary : .blue)
                    }
                    .buttonStyle(.plain)
                    .popover(isPresented: $showToolConfig) {
                        ToolSelectionView(
                            installed: installedTools,
                            selection: $selectedTools
                        )
                    }
                    .disabled(isScanning)
                }

                // Conditional branch.
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
                    Button(action: {
                        print("[ScanControlView] Start Scan button tapped!")
                        startScan()
                    }) {
                        Label("Start Scan", systemImage: "play.fill")
                    }
                    .disabled(
                        scanTarget.isEmpty
                            || !backend.isRunning
                            || (toolSelectionMode == .custom && selectedTools.isEmpty)
                    )
                    .onAppear {
                        print(
                            "[ScanControlView] Button disabled state: scanTarget.isEmpty=\(scanTarget.isEmpty), backend.isRunning=\(backend.isRunning), customModeEmpty=\(toolSelectionMode == .custom && selectedTools.isEmpty)"
                        )
                    }
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

    private func startScan() {
        print("[ScanControlView] startScan() called")
        print("[ScanControlView] scanTarget.isEmpty: \(scanTarget.isEmpty)")
        print("[ScanControlView] backend.isRunning: \(backend.isRunning)")
        print("[ScanControlView] appState: \(appState)")

        // Validate URL format
        guard let url = URL(string: scanTarget) else {
            print("[ScanControlView] Invalid URL format: \(scanTarget)")
            return
        }

        guard url.scheme == "http" || url.scheme == "https" else {
            print("[ScanControlView] Invalid URL scheme: \(url.scheme ?? "none")")
            return
        }

        // Conditional branch.
        if !scanTarget.isEmpty && backend.isRunning {
            print("[ScanControlView] Guard passed, proceeding to start scan")
            // Conditional branch.
            if toolSelectionMode == .custom && selectedTools.isEmpty {
                showToolConfig = true
                return
            }
            let modules: [String]
            // Switch over value.
            switch toolSelectionMode {
            case .scheduler:
                modules = []
            case .custom:
                modules = Array(selectedTools)
            }
            print(
                "[ScanControlView] Calling appState.startScan(target=\(scanTarget), modules=\(modules), mode=\(selectedMode.rawValue))"
            )
            appState.startScan(
                target: scanTarget, modules: modules, mode: selectedMode)
        } else {
            print(
                "[ScanControlView] Guard failed - scanTarget.isEmpty: \(scanTarget.isEmpty), backend.isRunning: \(backend.isRunning)"
            )
        }
    }
}

// MARK: - Subviews

/// Struct ToolSelectionView.
struct ToolSelectionView: View {
    let installed: [String]
    @Binding var selection: Set<String>

    var body: some View {
        VStack(alignment: .leading) {
            Text("Select Tools")
                .font(.headline)
                .padding(.bottom, 4)

            HStack {
                Button("Select All") {
                    selection = Set(installed)
                }
                Button("Clear") {
                    selection.removeAll()
                }
            }
            .buttonStyle(.link)
            .font(.caption)

            Divider()

            List {
                ForEach(installed, id: \.self) { tool in
                    HStack {
                        Image(systemName: selection.contains(tool) ? "checkmark.square" : "square")
                        Text(tool)
                        Spacer()
                    }
                    .contentShape(Rectangle())
                    .onTapGesture {
                        // Conditional branch.
                        if selection.contains(tool) {
                            selection.remove(tool)
                        } else {
                            selection.insert(tool)
                        }
                    }
                }
            }
            .frame(minWidth: 250, minHeight: 300)

            Text(selection.isEmpty ? "0 selected" : "\(selection.count) selected")
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .padding()
    }
}

// MARK: - Scan Progress Header
/// Struct ScanProgressHeader.
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

/// Struct FindingsListView.
struct FindingsListView: View {
    @EnvironmentObject var appState: HelixAppState

    var body: some View {
        List {
            Section(header: Text("Findings")) {
                // Conditional branch.
                if let findings = appState.apiResults?.findings {
                    ForEach(findings) { finding in
                        FindingRow(finding: finding)
                    }
                } else {
                    Text("No findings yet.")
                        .foregroundColor(.secondary)
                }
            }
        }
    }
}

/// Struct FindingRow.
struct FindingRow: View {
    let finding: FindingDTO

    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                Text(finding.type)
                    .font(.headline)
                Spacer()
                Text(finding.tool ?? "")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            Text(finding.message ?? finding.title ?? finding.description ?? "")
                .font(.caption)
                .lineLimit(2)
        }
        .padding(.vertical, 4)
        .textSelection(.enabled)
    }
}

/// Struct LogConsoleView.
struct LogConsoleView: View {
    @EnvironmentObject var appState: HelixAppState
    @State private var showingExporter = false
    @State private var logContentForExport: String = ""

    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                Text("Live Logs")
                    .font(.caption)
                    .bold()
                Spacer()
                Button("Clear") {
                    appState.clearLogs()
                }
                .buttonStyle(.plain)
                .font(.caption)

                Button("Export") {
                    // Extract text from log items
                    logContentForExport = appState.apiLogItems.map { $0.text }.joined(
                        separator: "\n")
                    showingExporter = true
                }
                .buttonStyle(.plain)
                .font(.caption)
                .disabled(appState.apiLogItems.isEmpty)
            }
            .padding(8)
            .background(Color(NSColor.controlBackgroundColor))

            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        ForEach(appState.apiLogItems) { item in
                            Text(item.text)
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundColor(.green)
                                .textSelection(.enabled)
                        }
                    }
                    .padding(8)
                }
                .onChange(of: appState.apiLogItems.count) { _, _ in
                    // Conditional branch.
                    if let last = appState.apiLogItems.last {
                        // Keep the newest scan activity visible. Avoid per-line animations to
                        // prevent stutter under high-volume logs.
                        DispatchQueue.main.async {
                            proxy.scrollTo(last.id, anchor: .bottom)
                        }
                    }
                }
            }
        }
        .background(Color.black)
        .fileExporter(
            isPresented: $showingExporter,
            document: PlainTextDocument(content: logContentForExport),
            contentType: .plainText,
            defaultFilename: "sentinel_logs.txt"
        ) { result in
            // Handle result (optional)
        }
    }
}

// Minimal FileDocument implementation
/// Struct PlainTextDocument.
struct PlainTextDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.plainText] }
    var content: String

    init(content: String) {
        self.content = content
    }

    init(configuration: ReadConfiguration) throws {
        // We only export, not import in this view
        content = ""
    }

    /// Function fileWrapper.
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        return FileWrapper(regularFileWithContents: content.data(using: .utf8)!)
    }
}
