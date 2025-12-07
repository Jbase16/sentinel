import Foundation

struct GenerateRequest: Encodable {
    let model: String
    let prompt: String
    let stream: Bool
}

struct GenerateChunk: Decodable {
    let response: String?
    let done: Bool?
}
