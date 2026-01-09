import Foundation

// MARK: - Core Entities

public struct FindingDTO: Identifiable, Codable, Equatable {
    public let id: String
    public let title: String?
    public let message: String?
    public let tool: String?
    public let type: String
    public let severity: String
    public let description: String?
    public let created_at: Double
}

// MARK: - Sentinel Results

public struct SentinelResults: Decodable {
    public let scan: ScanSummary?
    public let summary: ResultsSummary?
    public let findings: [FindingDTO]?
    public let issues: [JSONDict]?
    public let killchain: Killchain?
    public let phaseResults: [String: [JSONDict]]?
    public let evidence: [EvidenceSummary]?
    public let logs: [String]?

    enum CodingKeys: String, CodingKey {
        case scan, summary, findings, issues, killchain, logs, evidence
        case phaseResults = "phase_results"
    }
}

public struct ScanSummary: Decodable {
    public let target: String?
    public let modules: [String]?
    public let status: String?
    public let startedAt: String?
    public let finishedAt: String?
    public let durationMs: Int?
    public let error: String?

    enum CodingKeys: String, CodingKey {
        case target, modules, status, error
        case startedAt = "started_at"
        case finishedAt = "finished_at"
        case durationMs = "duration_ms"
    }
}

public struct ResultsSummary: Decodable {
    public let counts: ResultCounts?
    public let ai: AIStatus?
}

public struct ResultCounts: Decodable {
    public let findings: Int
    public let issues: Int
    public let killchainEdges: Int
    public let logs: Int
    public let phaseResults: [String: Int]

    enum CodingKeys: String, CodingKey {
        case findings, issues, logs
        case killchainEdges = "killchain_edges"
        case phaseResults = "phase_results"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        findings = try container.decodeIfPresent(Int.self, forKey: .findings) ?? 0
        issues = try container.decodeIfPresent(Int.self, forKey: .issues) ?? 0
        killchainEdges = try container.decodeIfPresent(Int.self, forKey: .killchainEdges) ?? 0
        logs = try container.decodeIfPresent(Int.self, forKey: .logs) ?? 0
        phaseResults =
            try container.decodeIfPresent([String: Int].self, forKey: .phaseResults) ?? [:]
    }
}

public struct Killchain: Decodable {
    public let edges: [JSONDict]?
    public let attackPaths: [[String]]?
    public let degradedPaths: [[String]]?
    public let recommendedPhases: [String]?

    enum CodingKeys: String, CodingKey {
        case edges
        case attackPaths = "attack_paths"
        case degradedPaths = "degraded_paths"
        case recommendedPhases = "recommended_phases"
    }
}

public struct EvidenceSummary: Decodable {
    public let id: Int
    public let tool: String?
    public let summary: String?
    public let metadata: JSONDict?
    public let rawPreview: String?
    public let rawBytes: Int?
    public let findingCount: Int?

    enum CodingKeys: String, CodingKey {
        case id, tool, summary, metadata
        case rawPreview = "raw_preview"
        case rawBytes = "raw_bytes"
        case findingCount = "finding_count"
    }
}

// MARK: - JSON Types

public enum JSONValue: Decodable {
    case string(String)
    case number(Double)
    case bool(Bool)
    case object([String: JSONValue])
    case array([JSONValue])
    case null

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let b = try? container.decode(Bool.self) {
            self = .bool(b)
        } else if let n = try? container.decode(Double.self) {
            self = .number(n)
        } else if let s = try? container.decode(String.self) {
            self = .string(s)
        } else if let arr = try? container.decode([JSONValue].self) {
            self = .array(arr)
        } else if let obj = try? container.decode([String: JSONValue].self) {
            self = .object(obj)
        } else {
            self = .null
        }
    }
}

public typealias JSONDict = [String: JSONValue]

extension JSONValue {
    public var stringValue: String? {
        switch self {
        case .string(let s): return s
        case .number(let n): return String(n)
        case .bool(let b): return String(b)
        default: return nil
        }
    }
}

// MARK: - Shared DTOs

public struct InstallResult: Decodable, Identifiable {
    public var id: String { tool }
    public let tool: String
    public let status: String
    public let message: String?
}

public struct SSEEvent {
    public let type: String
    public let data: String
}

public struct LogBatch: Decodable {
    public let lines: [String]
}

public struct EngineStatus: Decodable {
    public let status: String
    public let scanRunning: Bool
    public let latestTarget: String?
    public let ai: AIStatus?
    public let tools: ToolStatus?
    public let scanState: ScanStateDTO?
    public let cancelRequested: Bool?

    enum CodingKeys: String, CodingKey {
        case status, ai, tools
        case scanRunning = "scan_running"
        case latestTarget = "latest_target"
        case scanState = "scan_state"
        case cancelRequested = "cancel_requested"
    }
}

public struct ToolStatus: Decodable {
    public let installed: [String]
    public let missing: [String]
    public let countInstalled: Int
    public let countTotal: Int

    enum CodingKeys: String, CodingKey {
        case installed, missing
        case countInstalled = "count_installed"
        case countTotal = "count_total"
    }
}

public struct ScanStateDTO: Decodable {
    public let target: String?
    public let modules: [String]?
    public let status: String?
    public let startedAt: String?
    public let finishedAt: String?
    public let durationMs: Int?
    public let error: String?

    enum CodingKeys: String, CodingKey {
        case target, modules, status, error
        case startedAt = "started_at"
        case finishedAt = "finished_at"
        case durationMs = "duration_ms"
    }
}

public struct AIStatus: Decodable {
    public let provider: String?
    public let model: String?
    public let connected: Bool
    public let fallbackEnabled: Bool
    public let availableModels: [String]?
    public let circuitBreaker: CircuitBreakerState?

    enum CodingKeys: String, CodingKey {
        case provider, model, connected
        case fallbackEnabled = "fallback_enabled"
        case availableModels = "available_models"
        case circuitBreaker = "circuit_breaker"
    }
}

public struct CircuitBreakerState: Decodable {
    public let failureCount: Int
    public let threshold: Int
    public let isOpen: Bool
    public let openUntil: Double?
    public let timeRemaining: Double

    enum CodingKeys: String, CodingKey {
        case threshold
        case failureCount = "failure_count"
        case isOpen = "is_open"
        case openUntil = "open_until"
        case timeRemaining = "time_remaining"
    }
}

public struct AIStatusResponse: Decodable {
    public let provider: String
    public let model: String
    public let connected: Bool
    public let circuitBreaker: CircuitBreakerState

    enum CodingKeys: String, CodingKey {
        case provider, model, connected
        case circuitBreaker = "circuit_breaker"
    }
}

// MARK: - Errors

public enum APIError: Error {
    case badStatus
    case unauthorized
    case tokenNotFound
}
