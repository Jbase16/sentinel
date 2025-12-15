// ============================================================================
// ui/Sources/Services/ModelRouter.swift
// Modelrouter Component
// ============================================================================
//
// PURPOSE:
// This Swift component is part of the SentinelForge macOS UI.
// [Specific purpose based on component name: ModelRouter]
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

// Extremely simple heuristic model selector.
// Swap out rules here to prefer different Ollama models per prompt type.
struct ModelRouter {
    static let defaultPreferredModel = "llama3:latest"
    static let defaultCandidates = ["llama3:latest", "phi3:mini", "deepseek-coder:6.7b"]

    func routeModel(for prompt: String, preferredModel: String, autoRoutingEnabled: Bool, available: [String] = []) -> String {
        guard autoRoutingEnabled else { return preferredModel }
        let lower = prompt.lowercased()

        if lower.contains("func ")
            || lower.contains("class ")
            || lower.contains("struct ")
            || lower.contains("```")
            || lower.contains("swift")
            || lower.contains("stack trace")
            || lower.contains("error:") {
            return pickAvailable("deepseek-coder:6.7b", fallback: preferredModel, available: available)
        }

        if prompt.count < 120 {
            return pickAvailable("phi3:mini", fallback: preferredModel, available: available)
        }

        return pickAvailable("llama3:latest", fallback: preferredModel, available: available)
    }

    private func pickAvailable(_ candidate: String, fallback: String, available: [String]) -> String {
        guard !available.isEmpty else { return candidate }
        if available.contains(candidate) { return candidate }
        if available.contains(fallback) { return fallback }
        return available.first ?? candidate
    }

    func modelName(for prompt: String) -> String {
        routeModel(for: prompt, preferredModel: Self.defaultPreferredModel, autoRoutingEnabled: true)
    }
}
