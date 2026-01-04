//
//  PressureGraphModels.swift
//  SentinelForgeUI
//
//  DTOs for the Pressure Graph (Ground Truth) API.
//

import Foundation

public struct PressureGraphDTO: Decodable, Sendable {
    public let sessionId: String
    public let nodes: [PressureNodeDTO]
    public let edges: [PressureEdgeDTO]
    public let count: GraphCountDTO

    enum CodingKeys: String, CodingKey {
        case sessionId = "session_id"
        case nodes, edges, count
    }
}

public struct GraphCountDTO: Decodable, Sendable {
    public let nodes: Int
    public let edges: Int
}

public struct PressureNodeDTO: Decodable, Identifiable, Sendable {
    public let id: String
    public let type: String
    public let label: String?
    public let data: PressureNodeDataDTO

    enum CodingKeys: String, CodingKey {
        case id, type, label, data
    }
}

public struct PressureNodeDataDTO: Decodable, Sendable {
    public let severity: Double
    public let exposure: Double
    public let exploitability: Double
    public let privilegeGain: Double
    public let assetValue: Double
    public let pressureSource: String
    public let revision: Int

    enum CodingKeys: String, CodingKey {
        case severity, exposure, exploitability
        case privilegeGain = "privilege_gain"
        case assetValue = "asset_value"
        case pressureSource = "pressure_source"
        case revision
    }
}

public struct PressureEdgeDTO: Decodable, Identifiable, Sendable {
    public let id: String
    public let source: String
    public let target: String
    public let type: String
    public let weight: Double
    public let data: PressureEdgeDataDTO?

    enum CodingKeys: String, CodingKey {
        case id, source, target, type, weight, data
    }
}

public struct PressureEdgeDataDTO: Decodable, Sendable {
    public let confidence: Double
    public let createdAt: Double

    enum CodingKeys: String, CodingKey {
        case confidence
        case createdAt = "created_at"
    }
}
