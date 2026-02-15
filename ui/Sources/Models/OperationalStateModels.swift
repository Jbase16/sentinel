import Foundation

public struct P0Alert: Identifiable, Equatable {
    public let id = UUID()
    public let summary: String
    public let target: String
    public let path: String?
    public let createdAt: Date
}

public struct WAFStatus: Equatable {
    public let wafName: String
    public let lastUpdated: Date
}

public struct CapabilityBudgetSnapshot: Equatable {
    public let tokensRemaining: Int
    public let tokensMax: Int
    public let timeRemainingS: Double
    public let timeMaxS: Double
    public let actionsTaken: Int?
    public let isExhausted: Bool?

    public var tokensUsed: Int { max(0, tokensMax - tokensRemaining) }
    public var tokensProgress: Double {
        guard tokensMax > 0 else { return 0.0 }
        return min(1.0, max(0.0, Double(tokensUsed) / Double(tokensMax)))
    }

    public var timeUsedS: Double { max(0.0, timeMaxS - timeRemainingS) }
    public var timeProgress: Double {
        guard timeMaxS > 0 else { return 0.0 }
        return min(1.0, max(0.0, timeUsedS / timeMaxS))
    }
}

public struct CapabilityGateSnapshot: Equatable {
    public let executionMode: String
    public let tierCeiling: String?
    public let allowedTiers: [String]
    public let budget: CapabilityBudgetSnapshot?
}

