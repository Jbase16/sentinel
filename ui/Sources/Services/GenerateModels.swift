//
// PURPOSE:
// This Swift component is part of the SentinelForge macOS UI.
// [Specific purpose based on component name: GenerateModels]
//
// KEY RESPONSIBILITIES:
// - [Automatically generated - review and enhance based on actual functionality]
//
// INTEGRATION:
// - Used by: [To be documented]
// - Depends on: [To be documented]
//

import Foundation

/// Struct GenerateRequest.
struct GenerateRequest: Encodable {
    let model: String
    let prompt: String
    let stream: Bool
}

/// Struct GenerateChunk.
struct GenerateChunk: Decodable {
    let response: String?
    let done: Bool?
}
