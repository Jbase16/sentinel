import Combine
import RealityKit
import SwiftUI

/// Represents the live pressure state of a node
public struct PressureStateComponent: Component, Codable {
    public var pressure: Float = 0.0
    public var isFixed: Bool = false  // "Fixed" by user remediation

    public init(pressure: Float = 0.0, isFixed: Bool = false) {
        self.pressure = pressure
        self.isFixed = isFixed
    }
}

/// The System that animates the graph
public class PressureGraphSystem: System {

    private static let query = EntityQuery(where: .has(PressureStateComponent.self))

    // Store the reference to the Crown Jewel to measure total system instability
    public var crownJewel: Entity?
    private var accumulatedTime: Double = 0.0

    public required init(scene: RealityKit.Scene) {
        // System initialization
    }

    public func update(context: SceneUpdateContext) {
        accumulatedTime += context.deltaTime
        let t = Float(accumulatedTime)

        let entities = context.scene.performQuery(Self.query)

        for entity in entities {
            guard var state = entity.components[PressureStateComponent.self] else { continue }

            // If the node is "Fixed" (remediated), pressure decays rapidly
            if state.isFixed {
                state.pressure = max(0.0, state.pressure - 0.1)
            } else {
                // Simulate fluctuation around a target pressure
                let pos = entity.position
                let noise = sin(t * pos.x) * 0.05
                state.pressure = max(0.0, min(1.0, state.pressure + noise))
            }

            // Apply visual vibration
            if state.pressure > 0.0 {
                // Use Transform component directly
                var transform = entity.transform
                // Subtle vibration based on pressure
                // Subtle vibration logic left to shader to prevent position drift.
                let pulse = 1.0 + (sin(t * 4.0) * 0.1 * state.pressure)
                transform.scale = simd_float3(pulse, pulse, pulse)
                entity.transform = transform
            }

            entity.components[PressureStateComponent.self] = state
        }

        // Update Crown Jewel Visuals (The "System Heartbeat")
        // We find the crown jewel by name since we don't have a direct ref here automatically
        // In a real system we'd query for a CrownJewelComponent
    }
}
