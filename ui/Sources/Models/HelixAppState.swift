import Combine
import SwiftUI

// Holds shared UI + LLM state.
// ObservableObject means any @Published changes will re-render SwiftUI views.
@MainActor
class HelixAppState: ObservableObject {

    @Published var thread: ChatThread
    @Published var isProcessing: Bool = false
    @Published var currentTab: SidebarTab = .dashboard
    @Published var isScanRunning: Bool = false

    // Services
    let apiClient: SentinelAPIClient
    let cortexStream: CortexStream
    let ptyClient: PTYClient

    private var cancellables = Set<AnyCancellable>()

    @Published var apiLogs: [String] = []  // Buffered logs from Python core
    @Published var apiResults: SentinelResults?  // Latest scan snapshot
    @Published var engineStatus: EngineStatus?
    @Published var aiStatus: AIStatus?
    @Published var availableModels: [String] = ModelRouter.defaultCandidates
    @Published var preferredModel: String = ModelRouter.defaultPreferredModel
    @Published var autoRoutingEnabled: Bool = true
    @Published var pendingActions: [PendingAction] = []

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
        if let wsURL = URL(string: "ws://127.0.0.1:8765/ws/graph") {
            cortexStream.connect(url: wsURL)
        }
        if let ptyURL = URL(string: "ws://127.0.0.1:8765/ws/terminal") {
            ptyClient.connect(url: ptyURL)
        }
        // Kick off HTTP streams
        self.startEventStream()
        self.refreshStatus()
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

    convenience init() {
        self.init(llm: LLMService())
    }

    var modelOptions: [String] {
        let models = availableModels
        return models.isEmpty ? ModelRouter.defaultCandidates : models
    }

    // Reset conversation state.
    func clear() {
        thread = ChatThread(title: "Main Chat", messages: [])
    }

    // Append user message, create assistant bubble, and stream response from backend
    func send(_ text: String) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
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
            do {
                var accumulated = ""
                for try await token in apiClient.streamChat(prompt: trimmed) {
                    accumulated += token
                    await MainActor.run {
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
                    if let idx = self.thread.messages.firstIndex(where: { $0.id == replyID }) {
                        self.thread.messages[idx].text = "Error: \(error.localizedDescription)"
                    }
                    self.isProcessing = false
                }
            }
        }
    }

    // Allows UI Stop button to interrupt generation.
    func cancelGeneration() {
        // No-op for API-based chat
    }

    func updatePreferredModel(_ model: String) {
        llm.updatePreferredModel(model)
    }

    func updateAutoRouting(_ enabled: Bool) {
        llm.updateAutoRouting(enabled)
    }

    // MARK: - Core IPC Helpers (HTTP bridge to Python)

    /// Start a scan via the core /scan endpoint (supports logs + cancellation)
    func startScan(target: String) {
        print("[AppState] Starting Scan for target: \(target)")
        BackendManager.shared.isActiveOperation = true  // Scans can be long-running
        Task {
            defer {
                Task { @MainActor in
                    BackendManager.shared.isActiveOperation = false
                }
            }
            do {
                try await apiClient.startScan(target: target)
                await MainActor.run {
                    self.isScanRunning = true
                }
                // Light polling loop to keep UI fresh in case SSE misses events
                // Poll logs and results every 2s until scanRunning goes false
                Task { [weak self] in
                    while let self = self, self.isScanRunning {
                        self.refreshLogs()
                        self.refreshResults()
                        try? await Task.sleep(nanoseconds: 2 * 1_000_000_000)
                        // Optionally refresh status to detect completion
                        self.refreshStatus()
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
            if let lines = try? await apiClient.fetchLogs(), !lines.isEmpty {
                await MainActor.run {
                    self.apiLogs.append(contentsOf: lines)
                }
            }
        }
    }

    /// Fetch engine/AI status (model availability + running scan).
    func refreshStatus() {
        Task {
            if let status = try? await apiClient.fetchStatus() {
                await MainActor.run {
                    self.engineStatus = status
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
        }
    }

    /// Start SSE stream to receive real-time updates from Python
    func startEventStream() {
        Task {
            do {
                for try await event in apiClient.streamEvents() {
                    // handleSSEEvent is @MainActor but synchronous logic, so await isn't strictly needed
                    // for suspension, but MainActor isolation requires it if we weren't already on MainActor.
                    // However, since we are inside a Task, we are likely off-main.
                    // The warning "No async operations" suggests swift compiler sees it as synchronous.
                    // Let's rely on MainActor.run to be explicit and avoid the warning.
                    await MainActor.run {
                        self.handleSSEEvent(event)
                    }
                }
            } catch {
                print("[AppState] SSE Stream error: \(error), retrying in 5s...")
                try? await Task.sleep(nanoseconds: 5 * 1_000_000_000)
                startEventStream()
            }
        }
    }

    @MainActor
    private func handleSSEEvent(_ event: SSEEvent) {
        switch event.type {
        case "log":
            if let data = event.data.data(using: .utf8),
                let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                let line = json["line"] as? String
            {
                self.apiLogs.append(line)
            }
        case "findings_update", "evidence_update":
            // For now, just trigger a full refresh of results to keep it simple and consistent
            self.refreshResults()
        case "action_needed":
            if let data = event.data.data(using: .utf8),
                let action = try? JSONDecoder().decode(PendingAction.self, from: data)
            {
                // Avoid duplicates
                if !self.pendingActions.contains(where: { $0.id == action.id }) {
                    self.pendingActions.append(action)
                }
            }
        default:
            break
        }
    }

    func approveAction(_ action: PendingAction) {
        Task {
            try? await apiClient.approveAction(id: action.id)
            await MainActor.run {
                self.pendingActions.removeAll { $0.id == action.id }
            }
        }
    }

    func denyAction(_ action: PendingAction) {
        Task {
            try? await apiClient.denyAction(id: action.id)
            await MainActor.run {
                self.pendingActions.removeAll { $0.id == action.id }
            }
        }
    }
}

struct PendingAction: Identifiable, Decodable {
    let id: String
    let tool: String
    let args: [String]
    let reason: String?
    let target: String?
    let timestamp: String?
}

enum SidebarTab: String, CaseIterable, Identifiable {
    case dashboard = "Dashboard"
    case chat = "Command Deck"
    case graph = "Neural Graph"
    case settings = "Settings"

    var id: String { rawValue }
}
