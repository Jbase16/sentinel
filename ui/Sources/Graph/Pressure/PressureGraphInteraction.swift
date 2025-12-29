import AppKit
import RealityKit
import SwiftUI

// We assume PressureGraphSystem and PressureStateComponent are available in the same module.
// If they are in a different module, they must be imported.

struct PressureGraphInteraction: View {
    var body: some View {
        ZStack {
            Color.black.edgesIgnoringSafeArea(.all)

            VStack {
                Text("PRESSURE INTEGRITY MONITOR")
                    .font(.system(size: 20, weight: .heavy, design: .monospaced))
                    .foregroundColor(.green)
                    .padding(.top, 50)

                Spacer()

                // Simplified Container that handles setup internally
                PressureGraphARViewContainer()
                    .clipShape(RoundedRectangle(cornerRadius: 30))
                    .padding()

                Text("RIGHT CLICK VULNERABILITIES TO REMEDIATE")
                    .font(.caption)
                    .foregroundColor(.gray)
                    .padding(.bottom, 50)
            }
        }
    }
}

struct PressureGraphARViewContainer: NSViewRepresentable {

    func makeNSView(context: Context) -> ARView {
        let arView = ARView(frame: .zero)
        arView.environment.background = .color(.black)  // Dark void background

        // Setup the graph scene
        setupGraph(arView: arView, coordinator: context.coordinator)

        return arView
    }

    func updateNSView(_ nsView: ARView, context: Context) {
        // No updates needed from SwiftUI state for this demo
    }

    func makeCoordinator() -> Coordinator {
        Coordinator()
    }

    class Coordinator: NSObject {
        weak var arView: ARView?

        @objc func handleClick(_ sender: NSClickGestureRecognizer) {
            guard let arView = arView else { return }

            if sender.state == .ended {
                let location = sender.location(in: arView)
                // Perform raycast or hit test
                if let entity = arView.entity(at: location) as? ModelEntity {
                    remediate(entity: entity)
                }
            }
        }

        func remediate(entity: ModelEntity) {
            if var pComp = entity.components[PressureStateComponent.self] {
                pComp.isFixed = true
                entity.components[PressureStateComponent.self] = pComp

                // Visual feedback: Shrink
                var transform = entity.transform
                transform.scale = simd_float3(0.5, 0.5, 0.5)
                entity.move(to: transform, relativeTo: entity.parent, duration: 0.2)
            }
        }
    }

    // --- GRAPH GENERATION LOGIC ---

    private func setupGraph(arView: ARView, coordinator: Coordinator) {
        coordinator.arView = arView

        // 1. Scene Setup
        let scene = AnchorEntity(world: .zero)
        arView.scene.anchors.append(scene)

        // 2. Crown Jewel (The Anchor)
        // Using generateSphere instead of non-existent generateIcosahedron
        let crownJewel = ModelEntity(
            mesh: .generateSphere(radius: 0.3), materials: [createJewelMaterial()])
        crownJewel.position = simd_float3(0, 0, -1)
        crownJewel.name = "CrownJewel"

        // Custom light source
        let light = Entity()
        var lightComp = DirectionalLightComponent()
        lightComp.color = .blue
        lightComp.intensity = 1000
        light.components[DirectionalLightComponent.self] = lightComp
        light.look(at: .zero, from: .init(0, 10, 0), relativeTo: nil)
        scene.addChild(light)
        scene.addChild(crownJewel)

        // 3. Generate Network of Vulnerabilities
        let nodes = createVulnerabilityCluster(count: 30, target: crownJewel)
        nodes.forEach { scene.addChild($0) }

        // 4. Connect Nodes
        connectCluster(nodes: nodes, target: crownJewel, parent: scene)

        // 5. Register System
        PressureGraphSystem.registerSystem()

        // 6. Interaction
        // Manual gesture recognizer for macOS
        let click = NSClickGestureRecognizer(
            target: coordinator, action: #selector(Coordinator.handleClick(_:)))
        click.buttonMask = 0x2  // Right click
        arView.addGestureRecognizer(click)

        // Add Camera
        let camera = PerspectiveCamera()
        camera.look(at: .init(0, 0, -1), from: .init(0, 0, 1), relativeTo: nil)
        let cameraAnchor = AnchorEntity(world: .zero)
        cameraAnchor.addChild(camera)
        arView.scene.anchors.append(cameraAnchor)
    }

    private func createJewelMaterial() -> SimpleMaterial {
        var mat = SimpleMaterial()
        mat.color = .init(tint: .black)
        mat.metallic = .float(1.0)
        mat.roughness = .float(0.2)
        return mat
    }

    private func createVulnerabilityMaterial(pressure: Float) -> SimpleMaterial {
        var mat = SimpleMaterial()
        let color = lerpColor(from: .blue, to: .red, t: pressure)
        mat.color = .init(tint: color)
        mat.metallic = .float(0.8)
        mat.roughness = .float(0.4)
        return mat
    }

    private func createVulnerabilityCluster(count: Int, target: Entity) -> [AnchorEntity] {
        var anchors: [AnchorEntity] = []
        for i in 0..<count {
            let anchor = AnchorEntity(world: .zero)
            let radius: Float = 1.5
            let theta = Float(i) * 2.0 * .pi / Float(count)
            let phi = acos(1.0 - 2.0 * Float(i) / Float(count))
            let x = radius * sin(phi) * cos(theta)
            let y = radius * sin(phi) * sin(theta)
            let z = radius * cos(phi)
            let position = simd_float3(x, y, z - 1)

            let initialPressure = Float.random(in: 0.3...0.9)
            let mesh = MeshResource.generateBox(size: 0.08)
            let material = createVulnerabilityMaterial(pressure: initialPressure)
            let entity = ModelEntity(mesh: mesh, materials: [material])

            entity.position = position
            entity.look(at: target.position, from: position, relativeTo: nil)
            entity.name = "VulnNode_\(i)"

            // Add collision shape for raycasting
            entity.generateCollisionShapes(recursive: true)

            // Add Logic Component
            var pComp = PressureStateComponent()
            pComp.pressure = initialPressure
            pComp.isFixed = false
            entity.components[PressureStateComponent.self] = pComp

            anchor.addChild(entity)
            anchors.append(anchor)
        }
        return anchors
    }

    private func connectCluster(nodes: [AnchorEntity], target: Entity, parent: Entity) {
        for nodeAnchor in nodes {
            guard let node = nodeAnchor.children.first else { continue }
            let dist = distance(node.position, target.position)
            let midpoint = (node.position + target.position) / 2.0
            let beam = ModelEntity(
                mesh: .generateBox(size: [0.01, 0.01, dist]),
                materials: [UnlitMaterial(color: .cyan)])
            beam.position = midpoint
            beam.look(at: target.position, from: midpoint, relativeTo: nil)
            parent.addChild(beam)
        }
    }

    private func lerpColor(from: NSColor, to: NSColor, t: Float) -> NSColor {
        var fR: CGFloat = 0
        var fG: CGFloat = 0
        var fB: CGFloat = 0
        var fA: CGFloat = 0
        var tR: CGFloat = 0
        var tG: CGFloat = 0
        var tB: CGFloat = 0
        var tA: CGFloat = 0
        from.getRed(&fR, green: &fG, blue: &fB, alpha: &fA)
        to.getRed(&tR, green: &tG, blue: &tB, alpha: &tA)
        let r = fR + CGFloat(t) * (tR - fR)
        let g = fG + CGFloat(t) * (tG - fG)
        let b = fB + CGFloat(t) * (tB - fB)
        return NSColor(red: r, green: g, blue: b, alpha: 1.0)
    }
}
