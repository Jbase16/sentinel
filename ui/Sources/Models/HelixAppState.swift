//
// PURPOSE:
// This Swift component is part of the SentinelForge macOS UI.
// [Specific purpose based on component name: HelixAppState]
//
// KEY RESPONSIBILITIES:
// - [Automatically generated - review and enhance based on actual functionality]
//
// INTEGRATION:
// - Used by: [To be documented]
// - Depends on: [To be documented]
//

import Combine
import Foundation
import SwiftUI

// Scan Mode (Strategos)
/// Enum ScanMode.
enum ScanMode: String, CaseIterable, Identifiable {
    case standard = "standard"
    case bugBounty = "bug_bounty"
    case stealth = "stealth"

    var id: String { rawValue }

    var displayName: String {
        // Switch over value.
        switch self {
        case .standard: return "Standard"
        case .bugBounty: return "Bug Bounty"
        case .stealth: return "Stealth"
        }
    }
}

// Holds shared UI + LLM state.
// ObservableObject means any @Published changes will re-render SwiftUI views.
@MainActor
/// Class HelixAppState.
public class HelixAppState: ObservableObject {

    @Published var thread: ChatThread
    @Published var isProcessing: Bool = false
    @Published var currentTab: SidebarTab = .dashboard

    // MARK: - Centralized State
    /// Scan running state
    @Published var isScanRunning: Bool = false

    /// Log items
    @Published var apiLogItems: [LogItem] = []

    // Services
    let eventClient = EventStreamClient()
    let apiClient: SentinelAPIClient
    let cortexStream: CortexStream
    let ptyClient: PTYClient

    private var cancellables = Set<AnyCancellable>()
    private var didSetupEventStreamSubscriptions = false
    private var seenEventIDs: Set<String> = []
    // Sequence tracking moved to AppStore
    // private var eventSequenceEpoch: Int = 1
    // private var lastEventSequence: Int = 0

    @Published var apiLogs: [String] = []  // Buffered logs from Python core
    @Published var apiResults: SentinelResults?  // Latest scan snapshot
    @Published var engineStatus: EngineStatus?
    @Published var aiStatus: AIStatus?
    @Published var availableModels: [String] = ModelRouter.defaultCandidates
    @Published var preferredModel: String = ModelRouter.defaultPreferredModel
    @Published var autoRoutingEnabled: Bool = true
    @Published var pendingActions: [PendingAction] = []
    @Published var isGhostActive: Bool = false
    @Published var ghostPort: Int? = nil

    // Report State (Persisted)
    @Published var reportContent: [String: String] = [:]
    @Published var reportIsGenerating: Bool = false
    @Published var selectedSection: String = "executive_summary"

    private let llm: LLMService

    init(llm: LLMService) {
        self.llm = llm

        // Initialize Services
        self.apiClient = SentinelAPIClient()
        self.cortexStream = CortexStream()
        self.ptyClient = PTYClient()

        self.thread = ChatThread(title: "Main Chat", messages: [])
        self.availableModels = llm.availableModels
        self.preferredModel = llm.preferredModel
        self.autoRoutingEnabled = llm.autoRoutingEnabled

        // Wait for BackendManager to signal readiness
        NotificationCenter.default.addObserver(forName: .backendReady, object: nil, queue: .main) {
            [weak self] _ in
            Task { @MainActor in
                self?.connectServices()
            }
        }

        // Setup Combine bindings for LLM state
        setupLLMBindings()
    }

    private func connectServices() {
        print("[AppState] Backend Ready. Connecting Services...")
        // Conditional branch.
        if let wsURL = URL(string: "ws://127.0.0.1:8765/ws/graph") {
            cortexStream.connect(url: wsURL)
        }
        // Conditional branch.
        if let ptyURL = URL(string: "ws://127.0.0.1:8765/ws/pty") {
            ptyClient.connect(url: ptyURL)
        }
        // Kick off HTTP streams
        // self.startEventStream() // REMOVED: Unifying on EventStreamClient
        self.refreshStatus()

        // Conditional branch.
        if !didSetupEventStreamSubscriptions {
            didSetupEventStreamSubscriptions = true

            // Subscribe BEFORE connecting so we don't drop early replay events.
            eventClient.eventPublisher
                .receive(on: RunLoop.main)
                .sink { [weak self] event in
                    // Guard condition.
                    guard let self else { return }

                    // Deduplicate by immutable event UUID (survives backend restarts/replays).
                    if self.seenEventIDs.contains(event.id) {
                        return
                    }
                    self.seenEventIDs.insert(event.id)
                    // Conditional branch.
                    if self.seenEventIDs.count > 50_000 {
                        self.seenEventIDs.removeAll(keepingCapacity: true)
                    }

                    // Update scan-running state from the authoritative scan lifecycle events.
                    switch event.eventType {
                    case .scanStarted:
                        self.isScanRunning = true
                        let target = event.payload["target"]?.stringValue ?? "unknown"
                        let toolCount = (event.payload["modules"]?.value as? [Any])?.count ?? 0
                        self.apiLogItems.append(
                            LogItem(
                                id: UUID(), text: "[Scan] started: \(target) (\(toolCount) tools)"))
                    case .scanCompleted:
                        self.isScanRunning = false
                        self.refreshResults()
                    case .scanFailed:
                        self.isScanRunning = false
                        self.refreshResults()
                    case .scanPhaseChanged:
                        if let phase = event.payload["phase"]?.stringValue {
                            let text = "🔄 [Phase] Transitioned to \(phase)"
                            self.apiLogs.append(text)
                            self.apiLogItems.append(LogItem(id: UUID(), text: text))
                        }
                    case .decisionMade:
                        if let intent = event.payload["intent"]?.stringValue,
                            let reason = event.payload["reason"]?.stringValue
                        {
                            let text = "🧠 [Decision] \(intent) → \(reason)"
                            self.apiLogs.append(text)
                            self.apiLogItems.append(LogItem(id: UUID(), text: text))
                        }
                    case .actionNeeded:
                        if let action = self.decodeAction(from: event.payload) {
                            if !self.pendingActions.contains(where: { $0.id == action.id }) {
                                self.pendingActions.append(action)
                            }
                        }
                    case .findingCreated, .findingConfirmed, .findingDismissed, .toolCompleted:
                        self.refreshResults()
                    default:
                        break
                    }

                    // Render selected events into the Live Logs console.
                    let rendered = self.renderLiveLogLine(event: event)
                    // Guard condition.
                    guard let rendered else { return }

                    self.apiLogItems.append(LogItem(id: UUID(), text: rendered))
                }
                .store(in: &cancellables)
        }

        // Connect unified event stream (provides sequence IDs)
        eventClient.connect()
    }

    private func renderLiveLogLine(event: GraphEvent) -> String? {
        // Switch over value.
        switch event.eventType {
        case .log:
            return event.payload["message"]?.stringValue
                ?? event.payload["line"]?.stringValue
                ?? event.type

        case .scanStarted:
            let target = event.payload["target"]?.stringValue ?? "unknown"
            let toolCount = (event.payload["modules"]?.value as? [Any])?.count ?? 0
            return "[Scan] started: \(target) (\(toolCount) tools)"

        case .scanCompleted:
            let status = event.payload["status"]?.stringValue ?? "unknown"
            let findings = event.payload["findings_count"]?.intValue ?? 0
            let duration = event.payload["duration_seconds"]?.doubleValue ?? 0.0
            return String(
                format: "[Scan] %@(findings=%d, duration=%.1fs)", status, findings, duration)

        case .scanFailed:
            let error = event.payload["error"]?.stringValue ?? "unknown error"
            return "[Scan] error: \(error)"

        case .toolStarted:
            let tool = event.payload["tool"]?.stringValue ?? "unknown"
            return "[Tool] start: \(tool)"

        case .toolCompleted:
            let tool = event.payload["tool"]?.stringValue ?? "unknown"
            let exitCode = event.payload["exit_code"]?.intValue ?? 0
            let findings = event.payload["findings_count"]?.intValue ?? 0
            return "[Tool] done: \(tool) (exit=\(exitCode), findings=\(findings))"

        case .narrativeEmitted:
            // Layer 3 Narrative: The Primary UX
            let narrative = event.payload["narrative"]?.stringValue ?? "..."
            return "🧠 \(narrative)"

        default:
            return nil
        }
    }

    private func setupLLMBindings() {
        // Mirror the LLM's generating flag to the UI.
        llm.$isGenerating
            .receive(on: DispatchQueue.main)
            .sink { [weak self] generating in
                self?.isProcessing = generating
            }
            .store(in: &cancellables)

        llm.$preferredModel
            .receive(on: DispatchQueue.main)
            .sink { [weak self] model in
                self?.preferredModel = model
            }
            .store(in: &cancellables)

        llm.$autoRoutingEnabled
            .receive(on: DispatchQueue.main)
            .sink { [weak self] enabled in
                self?.autoRoutingEnabled = enabled
            }
            .store(in: &cancellables)

        llm.$availableModels
            .receive(on: DispatchQueue.main)
            .sink { [weak self] models in
                self?.availableModels = models
            }
            .store(in: &cancellables)
    }

    public convenience init() {
        self.init(llm: LLMService())
    }

    var modelOptions: [String] {
        let models = availableModels
        return models.isEmpty ? ModelRouter.defaultCandidates : models
    }

    // Reset conversation state.
    /// Function clear.
    func clear() {
        thread = ChatThread(title: "Main Chat", messages: [])
    }

    // Append user message, create assistant bubble, and stream response from backend
    /// Function send.
    func send(_ text: String) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        // Guard condition.
        guard !trimmed.isEmpty else { return }

        let userMessage = ChatMessage(role: .user, text: trimmed)
        objectWillChange.send()
        thread.messages.append(userMessage)

        let reply = ChatMessage(role: .assistant, text: "")
        objectWillChange.send()
        thread.messages.append(reply)
        let replyID = reply.id

        isProcessing = true
        BackendManager.shared.isActiveOperation = true  // Tell health monitor we're busy

        // Use streaming chat for real-time token display
        Task {
            defer {
                Task { @MainActor in
                    BackendManager.shared.isActiveOperation = false
                }
            }
            // Do-catch block.
            do {
                var accumulated = ""
                // Loop over items.
                for try await token in apiClient.streamChat(prompt: trimmed) {
                    accumulated += token
                    await MainActor.run {
                        // Conditional branch.
                        if let idx = self.thread.messages.firstIndex(where: { $0.id == replyID }) {
                            self.objectWillChange.send()
                            self.thread.messages[idx].text = accumulated
                        }
                    }
                }
                await MainActor.run {
                    self.isProcessing = false
                }
            } catch {
                await MainActor.run {
                    // Conditional branch.
                    if let idx = self.thread.messages.firstIndex(where: { $0.id == replyID }) {
                        self.thread.messages[idx].text = "Error: \(error.localizedDescription)"
                    }
                    self.isProcessing = false
                }
            }
        }
    }

    // Allows UI Stop button to interrupt generation.
    /// Function cancelGeneration.
    func cancelGeneration() {
        // No-op for API-based chat
    }

    /// Function updatePreferredModel.
    func updatePreferredModel(_ model: String) {
        llm.updatePreferredModel(model)
    }

    /// Function updateAutoRouting.
    func updateAutoRouting(_ enabled: Bool) {
        llm.updateAutoRouting(enabled)
    }

    // MARK: - Report Generation

    /// Function generateReport.
    func generateReport(section: String) {
        // Guard condition.
        guard !reportIsGenerating else { return }
        reportIsGenerating = true
        reportContent[section] = ""  // Clear previous content

        Task {
            defer {
                Task { @MainActor in
                    self.reportIsGenerating = false
                }
            }
            // Do-catch block.
            do {
                // Loop over items.
                for try await token in apiClient.streamReportSection(section: section) {
                    await MainActor.run {
                        self.reportContent[section, default: ""] += token
                    }
                }
            } catch {
                await MainActor.run {
                    self.reportContent[section, default: ""] +=
                        "\n[Error: \(error.localizedDescription)]"
                }
            }
        }
    }

    // MARK: - Core IPC Helpers (HTTP bridge to Python)

    /// Function clearLogs.
    func clearLogs() {
        self.apiLogs.removeAll()
        self.apiLogItems.removeAll()
    }

    /// Start a scan via the core /scan endpoint (supports logs + cancellation)
    func startScan(target: String, modules: [String] = [], mode: ScanMode = .standard) {
        let toolsDescription = modules.isEmpty ? "AUTO (all installed)" : "\(modules)"
        print(
            "[AppState] Starting Scan for target: \(target) tools: \(toolsDescription) mode: \(mode.rawValue)"
        )
        BackendManager.shared.isActiveOperation = true  // Scans can be long-running
        Task {
            defer {
                Task { @MainActor in
                    BackendManager.shared.isActiveOperation = false
                }
            }
            // Do-catch block.
            do {
                try await apiClient.startScan(target: target, modules: modules, mode: mode.rawValue)
                await MainActor.run {
                    self.isScanRunning = true
                }
                // Light polling loop to keep UI fresh in case SSE misses events
                // Poll logs and results every 2s until scanRunning goes false
                Task { [weak self] in
                    // While loop.
                    while let self = self, self.isScanRunning {
                        self.refreshLogs()
                        self.refreshResults()
                        try? await Task.sleep(nanoseconds: 2 * 1_000_000_000)
                        // Optionally refresh status to detect completion
                        self.refreshStatus()
                        // Conditional branch.
                        if let running = self.engineStatus?.scanRunning, running == false {
                            self.isScanRunning = false
                        }
                    }
                }
            } catch {
                print("[AppState] Failed to start scan: \(error)")
            }
        }
    }

    /// Poll for new log lines from Python and append to our buffer.
    func refreshLogs() {
        Task {
            // Conditional branch.
            if let lines = try? await apiClient.fetchLogs(), !lines.isEmpty {
                await MainActor.run {
                    self.mergePolledLogs(lines)
                }
            }
        }
    }

    /// Fetch engine/AI status (model availability + running scan).
    func refreshStatus() {
        Task {
            // Conditional branch.
            if let status = try? await apiClient.fetchStatus() {
                await MainActor.run {
                    self.engineStatus = status
                    // Conditional branch.
                    if let ai = status.ai {
                        self.aiStatus = ai
                        let models = ai.availableModels ?? []
                        self.llm.applyAvailability(
                            connected: ai.connected,
                            models: models.isEmpty ? self.availableModels : models,
                            defaultModel: ai.model
                        )
                    }
                }
            }
        }
    }

    /// Pull the latest scan snapshot (findings/issues/etc.) from Python.
    func refreshResults() {
        Task {
            // Conditional branch.
            if let results = try? await apiClient.fetchResults() {
                await MainActor.run {
                    self.apiResults = results
                }
            }
        }
    }

    /// Ask Python core to cancel any active scan.
    func cancelScan() {
        Task {
            try? await apiClient.cancelScan()
            await MainActor.run {
                self.isScanRunning = false
            }
            self.refreshStatus()
        }
    }

    private func decodeAction(from payload: [String: AnyCodable]) -> PendingAction? {
        guard let id = payload["id"]?.stringValue,
            let tool = payload["tool"]?.stringValue,
            let args = payload["args"]?.value as? [String]
        else { return nil }

        return PendingAction(
            id: id,
            tool: tool,
            args: args,
            reason: payload["reason"]?.stringValue,
            target: payload["target"]?.stringValue,
            timestamp: payload["timestamp"]?.stringValue
        )
    }

    @MainActor
    private func mergePolledLogs(_ lines: [String]) {
        // Guard condition.
        guard !lines.isEmpty else { return }

        // `/logs` returns a tail window; merge by finding the last seen line.
        let lastText = apiLogs.last
        let startIndex: Int
        // Conditional branch.
        if let lastText, let idx = lines.lastIndex(of: lastText) {
            startIndex = idx + 1
        } else {
            startIndex = 0
        }

        let newLines = startIndex < lines.count ? Array(lines[startIndex...]) : []
        // Guard condition.
        guard !newLines.isEmpty else { return }

        apiLogs.append(contentsOf: newLines)

        // Conditional branch.
        if !eventClient.isConnected {
            // Loop over items.
            for line in newLines {
                // let nextID = (apiLogItems.last?.id ?? 0) + 1
                apiLogItems.append(LogItem(id: UUID(), text: line))
            }
        }
    }

    /// Function approveAction.
    func approveAction(_ action: PendingAction) {
        Task {
            try? await apiClient.approveAction(id: action.id)
            await MainActor.run {
                self.pendingActions.removeAll { $0.id == action.id }
            }
        }
    }

    /// Function denyAction.
    func denyAction(_ action: PendingAction) {
        Task {
            try? await apiClient.denyAction(id: action.id)
            await MainActor.run {
                self.pendingActions.removeAll { $0.id == action.id }
            }
        }
    }

    /// Function toggleGhost.
    func toggleGhost() {
        Task {
            // Conditional branch.
            if isGhostActive {
                _ = try? await apiClient.stopGhost()
                await MainActor.run {
                    self.isGhostActive = false
                    self.ghostPort = nil
                }
            } else {
                // Do-catch block.
                do {
                    let port = try await apiClient.startGhost(port: 8080)
                    await MainActor.run {
                        self.isGhostActive = true
                        self.ghostPort = port
                    }
                } catch {
                    print("[AppState] Failed to start Ghost Protocol: \(error)")
                }
            }
        }
    }
}

/// Struct PendingAction.
struct PendingAction: Identifiable, Decodable {
    let id: String
    let tool: String
    let args: [String]
    let reason: String?
    let target: String?
    let timestamp: String?
}
