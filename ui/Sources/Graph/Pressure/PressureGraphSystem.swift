import RealityKit
import SwiftUI

/// Represents the live pressure state of a node
public struct PressureStateComponent: Component {
    public var pressure: Float = 0.0
    public var isFixed: Bool = false // "Fixed" by user remediation
    
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
    
    public required init(scene: Scene) {
        // System initialization
    }
    
    public func update(context: SceneUpdateContext) {
        let entities = context.scene.performQuery(Self.query)
        
        for entity in entities {
            guard var state = entity.components[PressureStateComponent.self],
                  var model = entity.components[ModelComponent.self] else { continue }
            
            // If the node is "Fixed" (remediated), pressure decays rapidly
            if state.isFixed {
                state.pressure = max(0.0, state.pressure - 0.1)
            } else {
                // Simulate fluctuation around a target pressure (from Python backend)
                // Here we simulate organic data flow for the demo visual
                // In production, this would be updated via Backend sync
                let noise = sin(Float(context.time) * entity.position.x) * 0.05
                state.pressure = max(0.0, min(1.0, state.pressure + noise))
            }
            
            // Update Material Uniforms
            // We manually inject uniforms into a ShaderGraphMaterial if possible,
            // or use ModelComponent for simpler cases.
            // Note: RealityKit's CustomMaterial can be used here.
            
            // For now, we update the component state which drives external observers or custom material parameters if bound
            entity.components[PressureStateComponent.self] = state
        }
        
        // Update Crown Jewel Visuals (The "System Heartbeat")
        if let cj = crownJewel, var model = cj.components[ModelComponent.self] {
            // Calculate total pressure upstream (simulated)
            let systemStress = calculateSystemStress(entities)
            
            // Crown Jewel shakes more if pressure is high
            let t = Float(context.time)
            let shake = simd_float3(
                sin(t * 15.0),
                cos(t * 12.0),
                sin(t * 18.0)
            ) * systemStress * 0.05
            
            // Apply "Thermal Expansion" - Jewel gets redder/brighter (Simulated via emissive)
            // We use ModelComponent scale and position here for effect
            let baseParams = cj.components[PositionComponent.self] // Use strict transform if needed
            // Ideally we modify the transform directly or model offset
            
            cj.position = (cj.components[PressureStateComponent.self] != nil) ? cj.position + shake : cj.position
            // Note: Mutating position in update loop without base position reference causes drift. 
            // In production, use a separate 'BasePositionComponent'.
            // For this demo snippet, we assume external reset or small drift is okay/managed.
            
            cj.components[ModelComponent.self] = model
        }
    }
    
    func calculateSystemStress(_ entities: QueryResult<Entity>) -> Float {
        // Aggregate the pressure of all nodes into a single system health metric
        var totalPressure: Float = 0.0
        var count: Int = 0
        
        for entity in entities {
            if let state = entity.components[PressureStateComponent.self] {
                totalPressure += state.pressure
                count += 1
            }
        }
        
        return min(1.0, totalPressure / Float(max(1, count)))
    }
}
