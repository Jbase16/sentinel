public struct FindingDTO: Identifiable, Codable, Equatable {
    public let id: String
    public let title: String
    public let type: String
    public let severity: String
    public let description: String?
    public let created_at: Double
}

public struct SentinelResults: Codable, Equatable {
    public let findings: [FindingDTO]
    public let scan_id: String?
    public let stats: [String: Int]?
}
