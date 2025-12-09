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

        // Kick off lightweight polling to keep logs/results fresh.
        beginPolling()
        refreshStatus()
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

    /// Start periodic polling for logs/results every few seconds.
    func beginPolling() {
        pollCancellable?.cancel()
        pollCancellable = Timer.publish(every: 2.0, on: .main, in: .common)
            .autoconnect()
            .sink { [weak self] _ in
                self?.refreshLogs()
                self?.refreshResults()
                self?.refreshStatus()
            }
    }

    /// Stop periodic polling (if needed later).
    func stopPolling() {
        pollCancellable?.cancel()
        pollCancellable = nil
    }
}
