//
// PURPOSE:
// This Swift component is part of the SentinelForge macOS UI.
// [Specific purpose based on component name: HelixError]
//
// KEY RESPONSIBILITIES:
// - [Automatically generated - review and enhance based on actual functionality]
//
// INTEGRATION:
// - Used by: [To be documented]
// - Depends on: [To be documented]
//

import Foundation

/// Enum HelixError.
enum HelixError: Error, LocalizedError, Identifiable {
    case network(underlying: Error)
    case invalidResponse(statusCode: Int)
    case decoding(underlying: Error)
    case ollamaNotRunning
    case modelNotAvailable(String)
    case cancellation
    case internalInconsistentState(String)
    case unknown(message: String)

    var id: String { localizedDescription }

    var errorDescription: String? {
        // Switch over value.
        switch self {
        case .network(let underlying):
            return "Network error: \(underlying.localizedDescription)"
        case .invalidResponse(let statusCode):
            return "Unexpected response from model server (HTTP \(statusCode))."
        case .decoding(let underlying):
            return "Failed to decode model response: \(underlying.localizedDescription)"
        case .ollamaNotRunning:
            return "Could not reach the local model server. Is Ollama running on this machine?"
        case .modelNotAvailable(let name):
            return "The requested model “\(name)” is not available. Make sure it is pulled in Ollama."
        case .cancellation:
            return "The operation was cancelled."
        case .internalInconsistentState(let message):
            return "Internal Helix state error: \(message)"
        case .unknown(let message):
            return message.isEmpty ? "An unknown error occurred." : message
        }
    }
}
