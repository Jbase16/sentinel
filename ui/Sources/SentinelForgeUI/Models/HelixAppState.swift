import SwiftUI
import Combine

// Holds shared UI + LLM state.
// ObservableObject means any @Published changes will re-render SwiftUI views.
@MainActor
class HelixAppState: ObservableObject {

    @Published var thread: ChatThread
    @Published var isProcessing: Bool = false
    @Published var apiLogs: [String] = []          // Buffered logs from Python core
    @Published var apiResults: SentinelResults?    // Latest scan snapshot
    @Published var engineStatus: EngineStatus?
    @Published var aiStatus: AIStatus?
    @Published var availableModels: [String] = ModelRouter.defaultCandidates
    @Published var preferredModel: String = ModelRouter.defaultPreferredModel
    @Published var autoRoutingEnabled: Bool = true
    @Published var pendingActions: [PendingAction] = []

    private let llm: LLMService
    private let api = SentinelAPIClient()
    private var cancellables = Set<AnyCancellable>()
    private var pollCancellable: AnyCancellable?

    init(llm: LLMService) {
        self.llm = llm
        self.thread = ChatThread(title: "Main Chat", messages: [])
        self.availableModels = llm.availableModels
        self.preferredModel = llm.preferredModel
        self.autoRoutingEnabled = llm.autoRoutingEnabled

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

        // Initialization is now lazy via onAppear in the View
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
    
    // Append user message, create an empty assistant bubble, and stream tokens into it.
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

        // Stream tokens directly into the assistant bubble.
        llm.generate(prompt: trimmed) { [weak self] token in
            guard let self else { return }
            if let idx = self.thread.messages.firstIndex(where: { $0.id == replyID }) {
                self.objectWillChange.send()
                self.thread.messages[idx].text += token
            }
        }
    }

    // Allows UI Stop button to interrupt generation.
    func cancelGeneration() {
        llm.cancel()
    }

    func updatePreferredModel(_ model: String) {
        llm.updatePreferredModel(model)
    }

    func updateAutoRouting(_ enabled: Bool) {
        llm.updateAutoRouting(enabled)
    }

    // MARK: - Core IPC Helpers (HTTP bridge to Python)

    /// Start a scan via the local Python API.
    func startScan(target: String) {
        Task {
            try? await api.startScan(target: target)
        }
    }

    /// Poll for new log lines from Python and append to our buffer.
    func refreshLogs() {
        Task {
            if let lines = try? await api.fetchLogs(), !lines.isEmpty {
                await MainActor.run {
                    self.apiLogs.append(contentsOf: lines)
                }
            }
        }
    }

    /// Fetch engine/AI status (model availability + running scan).
    func refreshStatus() {
        Task {
            if let status = try? await api.fetchStatus() {
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
            if let results = try? await api.fetchResults() {
                await MainActor.run {
                    self.apiResults = results
                }
            }
        }
    }

    /// Ask Python core to cancel any active scan.
    func cancelScan() {
        Task {
            try? await api.cancelScan()
        }
    }

    /// Start SSE stream to receive real-time updates from Python
    func startEventStream() {
        Task {
            do {
                for try await event in api.streamEvents() {
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
                let line = json["line"] as? String {
                 self.apiLogs.append(line)
             }
        case "findings_update", "evidence_update":
            // For now, just trigger a full refresh of results to keep it simple and consistent
            self.refreshResults()
        case "action_needed":
            if let data = event.data.data(using: .utf8),
               let action = try? JSONDecoder().decode(PendingAction.self, from: data) {
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
            try? await api.approveAction(id: action.id)
            await MainActor.run {
                self.pendingActions.removeAll { $0.id == action.id }
            }
        }
    }

    func denyAction(_ action: PendingAction) {
        Task {
            try? await api.denyAction(id: action.id)
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
