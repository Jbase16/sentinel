import Foundation
import Combine

// Thin wrapper around Ollama's HTTP API with streaming token support.
// This service is kept UI-friendly (ObservableObject) so SwiftUI can react
// to generation state changes automatically.
@MainActor
final class LLMService: ObservableObject {

    @Published var isGenerating: Bool = false
    @Published var streamedResponse: String = ""

    private let router = ModelRouter()
    private var currentTask: Task<Void, Never>?

    // Stop any in-flight generation and reset flags.
    func cancel() {
        currentTask?.cancel()
        currentTask = nil
        isGenerating = false
    }

    // Kick off a streaming generation call and deliver tokens to the caller.
    // onToken is invoked on the main actor so UI mutations are safe.
    func generate(prompt: String, onToken: @escaping (String) -> Void) {
        cancel()

        let trimmed = prompt.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }

        streamedResponse = ""
        isGenerating = true

        // Heuristic router decides which local model to use.
        let modelName = router.modelName(for: trimmed)

        currentTask = Task.detached { [weak self] in
            guard let self else { return }
            defer { Task { @MainActor in self.isGenerating = false } }

            guard let url = URL(string: "http://127.0.0.1:11434/api/generate") else {
                print("[LLMService] Invalid URL")
                return
            }

            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")

            let body = GenerateRequest(model: modelName, prompt: trimmed, stream: true)
            // Encode request body as JSON expected by Ollama.
            do {
                request.httpBody = try JSONEncoder().encode(body)
            } catch {
                print("[LLMService] Encoding error: \(error)")
                return
            }

            // Start streaming bytes, decoding each line as a GenerateChunk.
            do {
                let (bytes, _) = try await URLSession.shared.bytes(for: request)
                for try await line in bytes.lines {
                    if Task.isCancelled { break }
                    guard let data = line.data(using: .utf8) else { continue }
                    do {
                        let chunk = try JSONDecoder().decode(GenerateChunk.self, from: data)
                        if let token = chunk.response {
                            await MainActor.run {
                                self.streamedResponse += token
                                onToken(token)
                            }
                        }
                        if chunk.done == true { break }
                    } catch {
                        print("[LLMService] Chunk decode error: \(error)")
                        continue
                    }
                }
            } catch {
                if Task.isCancelled {
                    print("[LLMService] Cancelled")
                } else {
                    print("[LLMService] Request failed: \(error)")
                }
            }
        }
    }
}
