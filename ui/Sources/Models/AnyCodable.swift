//
//  AnyCodable.swift
//  SentinelForgeUI
//
//  Type-erased Codable wrapper.
//

import Foundation

public struct AnyCodable: Codable, @unchecked Sendable {
    public let value: Any

    public init<T>(_ value: T?) {
        self.value = value ?? ()
    }

    public init(_ value: Any) {
        self.value = value
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()

        if let intVal = try? container.decode(Int.self) {
            value = intVal
        } else if let doubleVal = try? container.decode(Double.self) {
            value = doubleVal
        } else if let boolVal = try? container.decode(Bool.self) {
            value = boolVal
        } else if let stringVal = try? container.decode(String.self) {
            value = stringVal
        } else if let arrayVal = try? container.decode([AnyCodable].self) {
            value = arrayVal.map { $0.value }
        } else if let dictVal = try? container.decode([String: AnyCodable].self) {
            var dictionary: [String: Any] = [:]
            for (key, val) in dictVal {
                dictionary[key] = val.value
            }
            value = dictionary
        } else {
            throw DecodingError.dataCorruptedError(
                in: container, debugDescription: "AnyCodable value cannot be decoded")
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()

        switch value {
        case let intVal as Int:
            try container.encode(intVal)
        case let doubleVal as Double:
            try container.encode(doubleVal)
        case let boolVal as Bool:
            try container.encode(boolVal)
        case let stringVal as String:
            try container.encode(stringVal)
        case let arrayVal as [Any]:
            try container.encode(arrayVal.map { AnyCodable($0) })
        case let dictVal as [String: Any]:
            try container.encode(dictVal.mapValues { AnyCodable($0) })
        default:
            throw EncodingError.invalidValue(
                value,
                EncodingError.Context(
                    codingPath: container.codingPath,
                    debugDescription: "AnyCodable value cannot be encoded"))
        }
    }

    // Helper to cast to String
    public var stringValue: String? {
        return value as? String
    }

    // Helper to cast to Double
    public var doubleValue: Double? {
        return value as? Double
    }

    // Helper to cast to Int
    public var intValue: Int? {
        return value as? Int
    }

    // Helper to cast to Dictionary
    public var dictValue: [String: Any]? {
        return value as? [String: Any]
    }
}
