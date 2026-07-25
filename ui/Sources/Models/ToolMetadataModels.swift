import Foundation

public struct ToolMetadataResponse: Decodable {
    public let tools: [String: ToolMetadata]
    public let modes: [String: ModeTierInfo]?
}

public struct ToolMetadata: Decodable, Equatable {
    public let name: String
    public let label: String?
    public let tier: String
    public let tierShort: String
    public let tierValue: Int

    enum CodingKeys: String, CodingKey {
        case name, label, tier
        case tierShort = "tier_short"
        case tierValue = "tier_value"
    }
}

public struct ModeTierInfo: Decodable, Equatable {
    public let tierCeiling: String?
    public let tierCeilingShort: String?
    public let allowedTiers: [String]

    enum CodingKeys: String, CodingKey {
        case tierCeiling = "tier_ceiling"
        case tierCeilingShort = "tier_ceiling_short"
        case allowedTiers = "allowed_tiers"
    }
}

