import Foundation

// Extremely simple heuristic model selector.
// Swap out rules here to prefer different Ollama models per prompt type.
struct ModelRouter {
    func routeModel(for prompt: String, preferredModel: String, autoRoutingEnabled: Bool) -> String {
        guard autoRoutingEnabled else { return preferredModel }
        let lower = prompt.lowercased()

        if lower.contains("func ")
            || lower.contains("class ")
            || lower.contains("struct ")
            || lower.contains("```")
            || lower.contains("swift")
            || lower.contains("stack trace")
            || lower.contains("error:") {
            return "deepseek-coder:6.7b"
        }

        if prompt.count < 120 {
            return "phi3:mini"
        }

        return "llama3:latest"
    }

    func modelName(for prompt: String) -> String {
        routeModel(for: prompt, preferredModel: "llama3:latest", autoRoutingEnabled: true)
    }
}
