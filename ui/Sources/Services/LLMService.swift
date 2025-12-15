// ============================================================================
// ui/Sources/Services/LLMService.swift
// Llmservice Component
// ============================================================================
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
// ============================================================================

import Foundation
import Combine

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
    private let api = SentinelAPIClient() // Chat now goes through Python API
    private var currentTask: Task<Void, Never>?

    // Stop any in-flight generation and reset flags.
    func cancel() {
        currentTask?.cancel()
        currentTask = nil
        isGenerating = false
    }

    func updatePreferredModel(_ model: String) {
        preferredModel = model
    }

    func updateAutoRouting(_ enabled: Bool) {
        autoRoutingEnabled = enabled
    }

    func applyAvailability(connected: Bool, models: [String], defaultModel: String? = nil) {
        ollamaOnline = connected
        let cleaned = models.filter { !$0.isEmpty }
        if !cleaned.isEmpty {
            availableModels = cleaned
            if let incoming = defaultModel, !incoming.isEmpty {
                preferredModel = incoming
            } else if !cleaned.contains(preferredModel) {
                preferredModel = cleaned.first ?? preferredModel
            }
        }
    }

    // Kick off a streaming generation call and deliver tokens to the caller.
    // onToken is invoked on the main actor so UI mutations are safe.
    func generate(prompt: String, onToken: @escaping (String) -> Void) {
        cancel()

        let trimmed = prompt.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }

        streamedResponse = ""
        isGenerating = true

        let client = self.api // Capture value type for detached task

        currentTask = Task.detached { [weak self] in
            guard let self else { return }
            defer { Task { @MainActor in self.isGenerating = false } }

            do {
                // Use the new Python API streamChat which is context-aware
                for try await token in client.streamChat(prompt: trimmed) {
                    if Task.isCancelled { break }
                    await MainActor.run {
                        self.streamedResponse += token
                        onToken(token)
                    }
                }
            } catch {
                if !Task.isCancelled {
                    print("[LLMService] Request failed: \(error)")
                    await MainActor.run {
                        onToken("\n[Error: \(error.localizedDescription)]")
                    }
                }
            }
        }
    }
}
