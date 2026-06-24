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
import AppKit

/// Enum ToolSelectionMode.
enum ToolSelectionMode: String, CaseIterable, Identifiable {
    case scheduler = "scheduler"
    case custom = "custom"

    var id: String { rawValue }

    var displayName: String {
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
    @State private var showAdvancedConfig = false
    @State private var personasJSON: String = ""
    @State private var oobJSON: String = ""

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

            if let p0 = appState.activeP0Alert {
                P0AlertBanner(alert: p0) { appState.activeP0Alert = nil }
            }

            if let waf = appState.wafStatus {
                WAFStatusBanner(waf: waf) { appState.wafStatus = nil }
            }

            // Scan Progress Header
            if isScanning {
                ScanProgressHeader(
                    logCount: appState.apiLogItems.count,
                    nodeCount: appState.cortexStream.nodes.count,
                    edgeCount: appState.cortexStream.edges.count,
                    startedAt: appState.scanStartTime,
                    capabilityGate: appState.capabilityGateSnapshot
                )
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
                    guard newMode == .custom else { return }
                    guard selectedTools.isEmpty, !installedTools.isEmpty else { return }
                    selectedTools = Set(installedTools)
                }
                .onChange(of: installedTools) { _, newInstalled in
                    guard toolSelectionMode == .custom else { return }
                    guard selectedTools.isEmpty, !newInstalled.isEmpty else { return }
                    selectedTools = Set(newInstalled)
                }

                // Tool Configuration
                if toolSelectionMode == .custom {
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

                Button(action: { showAdvancedConfig.toggle() }) {
                    Image(systemName: "slider.horizontal.3")
                        .foregroundColor(.secondary)
                }
                .buttonStyle(.plain)
                .popover(isPresented: $showAdvancedConfig) {
                    AdvancedScanConfigView(personasJSON: $personasJSON, oobJSON: $oobJSON)
                        .frame(width: 540, height: 420)
                        .environmentObject(appState)
                }
                .disabled(isScanning)

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
            HSplitView {
                FindingsListView()
                    .frame(minWidth: 300)

                LogConsoleView()
                    .frame(minWidth: 300)
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

        guard !scanTarget.isEmpty && backend.isRunning else {
            print(
                "[ScanControlView] Guard failed - scanTarget.isEmpty: \(scanTarget.isEmpty), backend.isRunning: \(backend.isRunning)"
            )
            return
        }

        print("[ScanControlView] Guard passed, proceeding to start scan")

        if toolSelectionMode == .custom && selectedTools.isEmpty {
            showToolConfig = true
            return
        }

        let modules: [String]
        switch toolSelectionMode {
        case .scheduler:
            modules = []
        case .custom:
            modules = Array(selectedTools)
        }

        print(
            "[ScanControlView] Calling appState.startScan(target=\(scanTarget), modules=\(modules), mode=\(selectedMode.rawValue))"
        )

        let personasTrimmed = personasJSON.trimmingCharacters(in: .whitespacesAndNewlines)
        let parsedPersonas = parseJSONArray(personasJSON)

        if !personasTrimmed.isEmpty && parsedPersonas == nil {
            print("[ScanControlView] Aborting startScan: invalid Personas JSON")
            return
        }

        let oobTrimmed = oobJSON.trimmingCharacters(in: .whitespacesAndNewlines)
        let parsedOob = parseJSONDict(oobJSON)

        if !oobTrimmed.isEmpty && parsedOob == nil {
            print("[ScanControlView] Aborting startScan: invalid OOB JSON")
            return
        }

        // Collect non-blank scope rules from appState
        let scopeLines = appState.scopeRules
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty && !$0.hasPrefix("#") }

        let bountyHandle = appState.bountyHandle.trimmingCharacters(in: .whitespacesAndNewlines)
        let bountyJSONTrimmed = appState.bountyJSONConfig.trimmingCharacters(
            in: .whitespacesAndNewlines
        )

        let parsedBountyJSON: [String: Any]?

        if bountyJSONTrimmed.isEmpty {
            parsedBountyJSON = nil
        } else {
            parsedBountyJSON = parseJSONDict(appState.bountyJSONConfig)

            if parsedBountyJSON == nil {
                print("[ScanControlView] Aborting startScan: invalid HackerOne JSON")
                return
            }
        }

        appState.startScan(
            target: scanTarget,
            modules: modules,
            mode: selectedMode,
            personas: parsedPersonas,
            oob: parsedOob,
            scope: scopeLines.isEmpty ? nil : scopeLines,
            scopeStrict: appState.scopeStrict,
            bountyHandle: bountyHandle.isEmpty ? nil : bountyHandle,
            bountyJSON: parsedBountyJSON
        )
    }

    private func parseJSONArray(_ text: String) -> [[String: Any]]? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        guard let data = trimmed.data(using: .utf8) else { return nil }

        do {
            let obj = try JSONSerialization.jsonObject(with: data)

            guard let arr = obj as? [[String: Any]] else {
                print("[ScanControlView] personasJSON must be a JSON array of objects")
                return nil
            }

            return arr
        } catch {
            print("[ScanControlView] personasJSON parse error: \(error)")
            return nil
        }
    }

    private func parseJSONDict(_ text: String) -> [String: Any]? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        guard let data = trimmed.data(using: .utf8) else { return nil }

        do {
            let obj = try JSONSerialization.jsonObject(with: data)

            guard let dict = obj as? [String: Any] else {
                print("[ScanControlView] oobJSON must be a JSON object")
                return nil
            }

            return dict
        } catch {
            print("[ScanControlView] oobJSON parse error: \(error)")
            return nil
        }
    }
}

private struct AdvancedScanConfigView: View {
    @EnvironmentObject var appState: HelixAppState
    @Binding var personasJSON: String
    @Binding var oobJSON: String

    /// Which tab is visible inside the popover
    @State private var tab: Int = 0

    /// Ephemeral text for the new-rule input field
    @State private var newRuleText: String = ""

    private let personasPlaceholder =
        """
        [
          {
            "name": "User",
            "persona_type": "user",
            "bearer_token": "REDACTED"
          },
          {
            "name": "Admin",
            "persona_type": "admin",
            "cookie_jar": { "session": "REDACTED" }
          }
        ]
        """

    private let oobPlaceholder =
        """
        {
          "provider": "interactsh",
          "base_domain": "oob.example.com",
          "api_url": "https://interactsh.com",
          "poll_timeout_s": 25,
          "poll_interval_s": 2
        }
        """

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Tab bar
            HStack {
                Text("Advanced Scan Config")
                    .font(.headline)

                Spacer()

                Picker("", selection: $tab) {
                    Text("Scope").tag(0)
                    Text("HackerOne").tag(1)
                    Text("Personas").tag(2)
                    Text("OOB").tag(3)
                }
                .pickerStyle(.segmented)
                .frame(width: 250)

                Button("Clear All") {
                    appState.scopeRules = []
                    appState.scopeStrict = false
                    appState.bountyHandle = ""
                    appState.bountyJSONConfig = ""
                    personasJSON = ""
                    oobJSON = ""
                }
                .buttonStyle(.link)
                .font(.caption)
            }
            .padding([.horizontal, .top])
            .padding(.bottom, 8)

            Divider()

            Group {
                if tab == 0 {
                    scopeTab
                } else if tab == 1 {
                    hackerOneTab
                } else if tab == 2 {
                    personasTab
                } else {
                    oobTab
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    // MARK: - Scope Tab

    private var scopeTab: some View {
        VStack(alignment: .leading, spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Scope Rules")
                    .font(.subheadline)
                    .bold()

                Text("One rule per line. Prefix with ! to exclude. Supports wildcards, CIDR, and /regex/.")
                    .font(.caption2)
                    .foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if appState.scopeRules.isEmpty {
                Text("No scope rules — all targets allowed (permissive mode).")
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding(.vertical, 8)
            } else {
                ScrollView {
                    VStack(spacing: 4) {
                        ForEach(Array(appState.scopeRules.enumerated()), id: \.offset) { idx, rule in
                            HStack(spacing: 6) {
                                ScopeRuleBadge(rule: rule)

                                Text(rule)
                                    .font(.system(size: 12, design: .monospaced))
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                                    .frame(maxWidth: .infinity, alignment: .leading)

                                Button(action: { appState.scopeRules.remove(at: idx) }) {
                                    Image(systemName: "xmark.circle.fill")
                                        .foregroundColor(.secondary)
                                }
                                .buttonStyle(.plain)
                            }
                            .padding(.horizontal, 8)
                            .padding(.vertical, 4)
                            .background(
                                rule.hasPrefix("!")
                                    ? Color.red.opacity(0.08)
                                    : Color.green.opacity(0.06)
                            )
                            .cornerRadius(4)
                        }
                    }
                }
                .frame(maxHeight: 140)
            }

            HStack(spacing: 6) {
                TextField(
                    "e.g. *.example.com  or  !staging.example.com  or  10.0.0.0/24",
                    text: $newRuleText
                )
                .textFieldStyle(.roundedBorder)
                .font(.system(size: 12, design: .monospaced))
                .onSubmit { addRule() }

                Button("Add", action: addRule)
                    .disabled(newRuleText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }

            Toggle(isOn: $appState.scopeStrict) {
                VStack(alignment: .leading, spacing: 1) {
                    Text("Strict mode")
                        .font(.caption)
                        .bold()

                    Text("Block requests to any target not explicitly in-scope (even with no inclusion rules).")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
            }
            .toggleStyle(.switch)
            .padding(.top, 2)

            Spacer()
        }
        .padding()
    }

    private func addRule() {
        let rule = newRuleText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !rule.isEmpty else { return }

        appState.scopeRules.append(rule)
        newRuleText = ""
    }

    // MARK: - HackerOne Tab

    private var hackerOneTab: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("HackerOne Integration")
                .font(.subheadline)
                .bold()

            Text("Provide a program handle (if authenticated via SENTINEL_H1_TOKEN) or paste the JSON payload from the HackerOne API.")
                .font(.caption2)
                .foregroundColor(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            HStack {
                Text("Handle:")
                    .font(.caption)
                    .frame(width: 60, alignment: .trailing)

                TextField("e.g. security-program", text: $appState.bountyHandle)
                    .textFieldStyle(.roundedBorder)
            }
            .padding(.top, 4)

            Text("Or paste JSON Configuration:")
                .font(.caption)
                .padding(.top, 4)

            ZStack(alignment: .topLeading) {
                TextEditor(text: $appState.bountyJSONConfig)
                    .font(.system(size: 11, design: .monospaced))
                    .frame(minHeight: 140)
                    .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.gray.opacity(0.25)))

                if appState.bountyJSONConfig.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    Text(
                        "{\n  \"handle\": \"example\",\n  \"in_scope\": [...],\n  \"out_of_scope\": [...]\n}"
                    )
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(.gray.opacity(0.6))
                    .padding(8)
                    .allowsHitTesting(false)
                }
            }

            Spacer()
        }
        .padding()
    }

    // MARK: - Personas Tab

    private var personasTab: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Personas (optional) – enables wraith_persona_diff when provided.")
                .font(.caption)
                .foregroundColor(.secondary)

            ZStack(alignment: .topLeading) {
                TextEditor(text: $personasJSON)
                    .font(.system(size: 11, design: .monospaced))
                    .frame(minHeight: 200)
                    .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.gray.opacity(0.25)))

                if personasJSON.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    Text(personasPlaceholder)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.gray.opacity(0.6))
                        .padding(8)
                        .allowsHitTesting(false)
                }
            }

            Spacer()
        }
        .padding()
    }

    // MARK: - OOB Tab

    private var oobTab: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("OOB (optional) – enables wraith_oob_probe when provided.")
                .font(.caption)
                .foregroundColor(.secondary)

            ZStack(alignment: .topLeading) {
                TextEditor(text: $oobJSON)
                    .font(.system(size: 11, design: .monospaced))
                    .frame(minHeight: 200)
                    .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.gray.opacity(0.25)))

                if oobJSON.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    Text(oobPlaceholder)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.gray.opacity(0.6))
                        .padding(8)
                        .allowsHitTesting(false)
                }
            }

            Spacer()
        }
        .padding()
    }
}

/// Small pill badge that shows the type of a scope rule.
private struct ScopeRuleBadge: View {
    let rule: String

    private var label: String {
        if rule.hasPrefix("!") { return "EXCL" }
        if rule.hasPrefix("/") && rule.hasSuffix("/") { return "REGEX" }
        if rule.contains("/") && rule.first?.isNumber == true { return "CIDR" }
        if rule.hasPrefix("*.") { return "WILD" }
        return "INCL"
    }

    private var color: Color {
        switch label {
        case "EXCL": return .red
        case "REGEX": return .purple
        case "CIDR": return .orange
        case "WILD": return .blue
        default: return .green
        }
    }

    var body: some View {
        Text(label)
            .font(.system(size: 9, weight: .bold, design: .monospaced))
            .foregroundColor(.white)
            .padding(.horizontal, 5)
            .padding(.vertical, 2)
            .background(color)
            .cornerRadius(3)
    }
}

// MARK: - Subviews

/// Struct ToolSelectionView.
struct ToolSelectionView: View {
    @EnvironmentObject var appState: HelixAppState
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

                        if let meta = appState.toolMetadata[tool] {
                            TierBadgeView(tierShort: meta.tierShort, tierValue: meta.tierValue)
                        }

                        Spacer()
                    }
                    .contentShape(Rectangle())
                    .onTapGesture {
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
    let nodeCount: Int
    let edgeCount: Int
    let startedAt: Date?
    let capabilityGate: CapabilityGateSnapshot?

    @State private var currentTime = Date()
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

            if let gate = capabilityGate {
                HStack(spacing: 12) {
                    Text("Execution: \(gate.executionMode.uppercased())")
                        .font(.caption2)
                        .foregroundColor(.secondary)

                    if let ceiling = gate.tierCeiling {
                        Text("Tier Ceiling: \(shortTierLabel(ceiling))")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }

                    Spacer()

                    if let budget = gate.budget {
                        Text("Tokens: \(budget.tokensRemaining)/\(budget.tokensMax)")
                            .font(.caption2)
                            .foregroundColor(.secondary)

                        Text("•")
                            .font(.caption2)
                            .foregroundColor(.secondary)

                        Text("Time: \(formatSeconds(budget.timeRemainingS))")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }
                }
            }

            if let budget = capabilityGate?.budget {
                VStack(spacing: 4) {
                    HStack {
                        Text("Budget (Tokens)")
                            .font(.caption2)
                            .foregroundColor(.secondary)

                        Spacer()

                        Text("\(budget.tokensUsed)/\(budget.tokensMax) used")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                            .monospacedDigit()
                    }

                    ProgressView(value: budget.tokensProgress)
                        .progressViewStyle(.linear)

                    HStack {
                        Text("Budget (Time)")
                            .font(.caption2)
                            .foregroundColor(.secondary)

                        Spacer()

                        Text(
                            "\(formatSeconds(budget.timeUsedS))/\(formatSeconds(budget.timeMaxS)) used"
                        )
                        .font(.caption2)
                        .foregroundColor(.secondary)
                        .monospacedDigit()
                    }

                    ProgressView(value: budget.timeProgress)
                        .progressViewStyle(.linear)
                }
            }

            HStack(spacing: 16) {
                Text("\(logCount) logs")
                    .font(.caption2)
                    .foregroundColor(.secondary)

                Text("•")
                    .font(.caption2)
                    .foregroundColor(.secondary)

                Text("\(nodeCount) nodes")
                    .font(.caption2)
                    .foregroundColor(.secondary)

                Text("•")
                    .font(.caption2)
                    .foregroundColor(.secondary)

                Text("\(edgeCount) edges")
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
                currentTime = Date()
            }
        }
        .onDisappear {
            timer?.invalidate()
        }
    }

    private var formattedTime: String {
        guard let startedAt = startedAt else {
            return "00:00"
        }

        let elapsed = Int(currentTime.timeIntervalSince(startedAt))
        let mins = elapsed / 60
        let secs = elapsed % 60

        return String(format: "%02d:%02d", mins, secs)
    }

    private func formatSeconds(_ seconds: Double) -> String {
        let s = max(0, Int(seconds.rounded()))
        let mins = s / 60
        let secs = s % 60

        if mins >= 60 {
            let hrs = mins / 60
            let rem = mins % 60
            return String(format: "%dh%02dm", hrs, rem)
        }

        return String(format: "%dm%02ds", mins, secs)
    }

    private func shortTierLabel(_ tierCeiling: String) -> String {
        if tierCeiling.contains("T0") { return "T0" }
        if tierCeiling.contains("T1") { return "T1" }
        if tierCeiling.contains("T2a") { return "T2a" }
        if tierCeiling.contains("T2b") { return "T2b" }
        if tierCeiling.contains("T3") { return "T3" }
        if tierCeiling.contains("T4") { return "T4" }

        return tierCeiling
    }
}

/// Struct FindingsListView.
struct FindingsListView: View {
    @EnvironmentObject var appState: HelixAppState
    @State private var hideDuplicates: Bool = false
    @State private var severityFilter: String = "ALL"

    private let severityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    private var filteredFindings: [FindingDTO] {
        guard let all = appState.apiResults?.findings else { return [] }

        return all.filter { finding in
            if hideDuplicates, finding.duplicateInfo?.isDuplicate == true {
                return false
            }

            if severityFilter != "ALL" {
                return finding.severity.uppercased() == severityFilter
            }

            return true
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                Toggle("Hide dupes", isOn: $hideDuplicates)
                    .toggleStyle(.checkbox)
                    .font(.caption)

                Spacer()

                Picker("Severity", selection: $severityFilter) {
                    Text("All").tag("ALL")

                    ForEach(severityOrder, id: \.self) { severity in
                        Text(severity.capitalized).tag(severity)
                    }
                }
                .pickerStyle(.menu)
                .font(.caption)
                .frame(maxWidth: 120)

                let total = appState.apiResults?.findings?.count ?? 0
                let showing = filteredFindings.count

                Text("\(showing)/\(total)")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
            .background(Color(NSColor.controlBackgroundColor))

            Divider()

            List {
                Section(header: Text("Findings")) {
                    if filteredFindings.isEmpty {
                        Text(
                            appState.apiResults?.findings?.isEmpty == false
                                ? "All findings filtered out."
                                : "No findings yet."
                        )
                        .foregroundColor(.secondary)
                    } else {
                        ForEach(filteredFindings) { finding in
                            FindingRow(finding: finding)
                        }
                    }
                }
            }
        }
    }
}

/// Struct FindingRow.
struct FindingRow: View {
    let finding: FindingDTO

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                SeverityBadge(severity: finding.severity)

                Text(finding.type)
                    .font(.system(size: 13, weight: .semibold))
                    .lineLimit(1)

                Spacer()

                if let dupe = finding.duplicateInfo {
                    DupeBadge(info: dupe)
                }

                Text(finding.tool ?? "")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }

            Text(finding.message ?? finding.title ?? finding.description ?? "")
                .font(.caption)
                .foregroundColor(.secondary)
                .lineLimit(2)

            if let asset = finding.asset ?? finding.target {
                Text(asset)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(.secondary)
                    .lineLimit(1)
            }
        }
        .padding(.vertical, 4)
        .textSelection(.enabled)
    }
}

/// Colored pill showing CRIT / HIGH / MEDI / LOW / INFO.
private struct SeverityBadge: View {
    let severity: String

    var body: some View {
        Text(severity.prefix(4).uppercased())
            .font(.system(size: 9, weight: .black, design: .monospaced))
            .foregroundColor(.white)
            .padding(.horizontal, 5)
            .padding(.vertical, 2)
            .background(severityColor(severity))
            .cornerRadius(3)
    }
}

/// Badge shown when a finding was seen in a previous scan.
private struct DupeBadge: View {
    let info: DuplicateInfo

    var body: some View {
        if info.isDuplicate {
            Text("DUPE ×\(info.seenCount)")
                .font(.system(size: 9, weight: .bold, design: .monospaced))
                .foregroundColor(.white)
                .padding(.horizontal, 5)
                .padding(.vertical, 2)
                .background(Color.purple.opacity(0.85))
                .cornerRadius(3)
                .help(info.annotation ?? "Seen in a previous scan")
        }
    }
}

/// Helper model for NSTableView rows.
private struct SelectableLogLine: Identifiable, Hashable {
    let id: String
    let text: String
}

/// Struct LogConsoleView.
struct LogConsoleView: View {
    @EnvironmentObject var appState: HelixAppState
    @State private var showingExporter = false
    @State private var logContentForExport: String = ""

    private var selectableLines: [SelectableLogLine] {
        appState.apiLogItems.map { item in
            SelectableLogLine(
                id: String(describing: item.id),
                text: item.text
            )
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
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
                    logContentForExport = appState.apiLogItems
                        .map { $0.text }
                        .joined(separator: "\n")

                    showingExporter = true
                }
                .buttonStyle(.plain)
                .font(.caption)
                .disabled(appState.apiLogItems.isEmpty)
            }
            .padding(8)
            .background(Color(NSColor.controlBackgroundColor))

            SelectableLogTableView(lines: selectableLines)
                .background(Color.black)
        }
        .background(Color.black)
        .fileExporter(
            isPresented: $showingExporter,
            document: PlainTextDocument(content: logContentForExport),
            contentType: .plainText,
            defaultFilename: "sentinel_logs.txt"
        ) { _ in
            // Handle result if needed.
        }
    }
}

// AppKit-backed selectable table view to enable Finder-style row selection.
private struct SelectableLogTableView: NSViewRepresentable {
    let lines: [SelectableLogLine]

    func makeNSView(context: Context) -> NSScrollView {
        let scrollView = NSScrollView()
        scrollView.hasVerticalScroller = true
        scrollView.hasHorizontalScroller = true
        scrollView.autohidesScrollers = false
        scrollView.borderType = .noBorder
        scrollView.drawsBackground = true
        scrollView.backgroundColor = .black

        let tableView = CopyableLogTableView()
        tableView.delegate = context.coordinator
        tableView.dataSource = context.coordinator
        tableView.headerView = nil
        tableView.backgroundColor = .black
        tableView.gridStyleMask = []
        tableView.rowHeight = 18
        tableView.allowsMultipleSelection = true
        tableView.allowsEmptySelection = true
        tableView.allowsColumnSelection = false
        tableView.usesAlternatingRowBackgroundColors = false
        tableView.selectionHighlightStyle = .regular
        tableView.columnAutoresizingStyle = .uniformColumnAutoresizingStyle

        let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("logLine"))
        column.title = "Log"
        column.resizingMask = [.autoresizingMask, .userResizingMask]
        column.minWidth = 300
        tableView.addTableColumn(column)

        scrollView.documentView = tableView

        context.coordinator.tableView = tableView
        context.coordinator.scrollView = scrollView
        context.coordinator.lines = lines

        tableView.reloadData()
        context.coordinator.scrollToBottom()

        return scrollView
    }

    func updateNSView(_ scrollView: NSScrollView, context: Context) {
        let oldCount = context.coordinator.lines.count
        let newCount = lines.count

        guard let tableView = context.coordinator.tableView else { return }

        let wasNearBottom = context.coordinator.isNearBottom()

        context.coordinator.lines = lines
        tableView.reloadData()
        context.coordinator.syncSelectedLogLines()

        if newCount > oldCount && wasNearBottom {
            DispatchQueue.main.async {
                context.coordinator.scrollToBottom()
            }
        }
    }

    func makeCoordinator() -> Coordinator {
        Coordinator()
    }

    final class Coordinator: NSObject, NSTableViewDataSource, NSTableViewDelegate {
        var lines: [SelectableLogLine] = []
        weak var tableView: CopyableLogTableView?
        weak var scrollView: NSScrollView?

        func numberOfRows(in tableView: NSTableView) -> Int {
            lines.count
        }

        func tableView(
            _ tableView: NSTableView,
            viewFor tableColumn: NSTableColumn?,
            row: Int
        ) -> NSView? {
            guard row >= 0, row < lines.count else { return nil }

            let identifier = NSUserInterfaceItemIdentifier("logCell")
            let cell: NSTableCellView

            if let reused = tableView.makeView(withIdentifier: identifier, owner: self) as? NSTableCellView {
                cell = reused
            } else {
                cell = NSTableCellView()
                cell.identifier = identifier

                let textField = NSTextField(labelWithString: "")
                textField.translatesAutoresizingMaskIntoConstraints = false
                textField.isSelectable = false
                textField.isEditable = false
                textField.drawsBackground = false
                textField.backgroundColor = .clear
                textField.textColor = .systemGreen
                textField.font = NSFont.monospacedSystemFont(ofSize: 11, weight: .regular)
                textField.lineBreakMode = .byClipping
                textField.maximumNumberOfLines = 1

                cell.textField = textField
                cell.addSubview(textField)

                NSLayoutConstraint.activate([
                    textField.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 8),
                    textField.trailingAnchor.constraint(equalTo: cell.trailingAnchor, constant: -8),
                    textField.centerYAnchor.constraint(equalTo: cell.centerYAnchor)
                ])
            }

            cell.textField?.stringValue = lines[row].text
            cell.textField?.textColor = .systemGreen

            return cell
        }

        func tableViewSelectionDidChange(_ notification: Notification) {
            syncSelectedLogLines()
        }

        func syncSelectedLogLines() {
            guard let tableView else { return }

            tableView.selectedLogLines = tableView.selectedRowIndexes.compactMap { index in
                guard index >= 0, index < lines.count else { return nil }
                return lines[index].text
            }
        }

        func isNearBottom() -> Bool {
            guard let scrollView else { return true }

            let visibleRect = scrollView.contentView.bounds
            let documentHeight = scrollView.documentView?.bounds.height ?? 0
            let visibleMaxY = visibleRect.maxY

            return documentHeight - visibleMaxY < 40
        }

        func scrollToBottom() {
            guard let tableView else { return }

            let lastRow = lines.count - 1
            guard lastRow >= 0 else { return }

            tableView.scrollRowToVisible(lastRow)
        }
    }
}

// NSTableView subclass to support Command-C copying of selected rows.
private final class CopyableLogTableView: NSTableView {
    var selectedLogLines: [String] = []

    override var acceptsFirstResponder: Bool {
        true
    }

    @objc func copy(_ sender: Any?) {
        copySelectedRowsToPasteboard()
    }

    override func validateUserInterfaceItem(_ item: NSValidatedUserInterfaceItem) -> Bool {
        if item.action == #selector(copy(_:)) {
            return !selectedLogLines.isEmpty
        }

        return super.validateUserInterfaceItem(item)
    }

    override func keyDown(with event: NSEvent) {
        let isCommandC =
            event.modifierFlags.contains(.command)
            && event.charactersIgnoringModifiers?.lowercased() == "c"

        if isCommandC {
            copySelectedRowsToPasteboard()
            return
        }

        super.keyDown(with: event)
    }

    private func copySelectedRowsToPasteboard() {
        guard !selectedLogLines.isEmpty else { return }

        let text = selectedLogLines.joined(separator: "\n")

        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}

// Minimal FileDocument implementation.
struct PlainTextDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.plainText] }

    var content: String

    init(content: String) {
        self.content = content
    }

    init(configuration: ReadConfiguration) throws {
        // We only export, not import in this view.
        content = ""
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        guard let data = content.data(using: .utf8) else {
            throw CocoaError(.fileWriteUnknown)
        }

        return FileWrapper(regularFileWithContents: data)
    }
}

