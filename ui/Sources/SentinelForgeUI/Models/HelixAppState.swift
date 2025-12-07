import SwiftUI
import Combine

// Holds shared UI + LLM state.
// ObservableObject means any @Published changes will re-render SwiftUI views.
@MainActor
class HelixAppState: ObservableObject {

    @Published var thread: ChatThread
    @Published var isProcessing: Bool = false

    private let llm: LLMService
    private var cancellables = Set<AnyCancellable>()

    init(llm: LLMService) {
        self.llm = llm
        self.thread = ChatThread(title: "Main Chat", messages: [])

        // Mirror the LLM's generating flag to the UI.
        llm.$isGenerating
            .receive(on: DispatchQueue.main)
            .sink { [weak self] generating in
                self?.isProcessing = generating
            }
            .store(in: &cancellables)
    }

    convenience init() {
        self.init(llm: LLMService())
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
}
