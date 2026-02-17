//
// PURPOSE:
// This Swift component is part of the SentinelForge macOS UI.
// [Specific purpose based on component name: LLMService]
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

// Thin wrapper around Ollama's HTTP API with streaming token support.
// This service is kept UI-friendly (ObservableObject) so SwiftUI can react
// to generation state changes automatically.
@MainActor
final class LLMService: ObservableObject {

    @Published var isGenerating: Bool = false
    @Published var streamedResponse: String = ""
    @Published var preferredModel: String = ModelRouter.defaultPreferredModel
    @Published var autoRoutingEnabled: Bool = true
    @Published var availableModels: [String] = ModelRouter.defaultCandidates
    @Published var ollamaOnline: Bool = true

    private let router = ModelRouter()
    private let api = SentinelAPIClient()  // Chat now goes through Python API
    private var currentTask: Task<Void, Never>?

    // Stop any in-flight generation and reset flags.
    /// Function cancel.
    func cancel() {
        currentTask?.cancel()
        currentTask = nil
        isGenerating = false
    }

    /// Function updatePreferredModel.
    func updatePreferredModel(_ model: String) {
        preferredModel = model
    }

    /// Function updateAutoRouting.
    func updateAutoRouting(_ enabled: Bool) {
        autoRoutingEnabled = enabled
    }

    /// Function applyAvailability.
    func applyAvailability(connected: Bool, models: [String], defaultModel: String? = nil) {
        ollamaOnline = connected
        let cleaned = models.filter { !$0.isEmpty }
        // Conditional branch.
        if !cleaned.isEmpty {
            availableModels = cleaned
            // Conditional branch.
            if let incoming = defaultModel, !incoming.isEmpty {
                preferredModel = incoming
            } else if !cleaned.contains(preferredModel) {
                preferredModel = cleaned.first ?? preferredModel
            }
        }
    }

    // Kick off a streaming generation call and deliver tokens to the caller.
    // onToken is invoked on the main actor so UI mutations are safe.
    /// Function generate.
    func generate(prompt: String, sessionID: String? = nil, onToken: @escaping (String) -> Void) {
        cancel()

        let trimmed = prompt.trimmingCharacters(in: .whitespacesAndNewlines)
        // Guard condition.
        guard !trimmed.isEmpty else { return }

        streamedResponse = ""
        isGenerating = true

        let client = self.api  // Capture value type for detached task

        currentTask = Task.detached { [weak self] in
            // Guard condition.
            guard let self else { return }
            defer { Task { @MainActor in self.isGenerating = false } }

            // Do-catch block.
            do {
                // Use the Python API streamChat which streams plain text chunks
                for try await token in client.streamChat(prompt: trimmed, sessionID: sessionID) {
                    // Conditional branch.
                    if Task.isCancelled { break }
                    await MainActor.run {
                        self.streamedResponse += token
                        onToken(token)
                    }
                }
            } catch {
                // Conditional branch.
                if !Task.isCancelled {
                    print("[LLMService] Request failed: \(error)")
                    await MainActor.run {
                        onToken("\n[Error: \(error.localizedDescription)]")
                    }
                }
            }
        }
    }
    // MARK: - Publishers for HelixAppState Binding

    /// Publishes streamed tokens (alias for streamedResponse for bindings)
    var textStream: AnyPublisher<String, Never> {
        $streamedResponse.eraseToAnyPublisher()
    }

    /// Publishes processing state (alias for isGenerating for bindings)
    var isProcessingPublisher: AnyPublisher<Bool, Never> {
        $isGenerating.eraseToAnyPublisher()
    }

    // Legacy support property
    var isProcessing: AnyPublisher<Bool, Never> { isProcessingPublisher }

    // Thread binding support - LLMService doesn't own the whole thread anymore,
    // but we provide a publisher that HelixAppState can bind to if needed.
    // For now, we'll expose a PassthroughSubject that AppState can drive,
    // or just rely on the fact that AppState owns the thread.
    // However, to fix the specific error 'Value of type LLMService has no member threadPublisher':
    private let _threadPublisher = PassthroughSubject<ChatThread, Never>()
    var threadPublisher: AnyPublisher<ChatThread, Never> {
        _threadPublisher.eraseToAnyPublisher()
    }
}
