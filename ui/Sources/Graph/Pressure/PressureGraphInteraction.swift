import RealityKit
import SwiftUI
import UIKit  // for UIColor

struct PressureGraphInteraction: View {
    @State private var arView: ARView?

    var body: some View {
        ZStack {
            Color.black.edgesIgnoringSafeArea(.all)

            VStack {
                Text("PRESSURE INTEGRITY MONITOR")
                    .font(.system(size: 20, weight: .heavy, design: .monospaced))
                    .foregroundColor(.green)
                    .padding(.top, 50)

                Spacer()

                ARViewContainer { arView in
                    self.arView = arView
                    setupGraph(arView: arView)
                }
                .clipShape(RoundedRectangle(cornerRadius: 30))
                .padding()

                Text("GRIP VULNERABILITIES TO REMEDIATE")
                    .font(.caption)
                    .foregroundColor(.gray)
                    .padding(.bottom, 50)
            }
        }
    }

    // --- GRAPH GENERATION ---

    func setupGraph(arView: ARView) {
        // 1. Scene Setup
        let scene = AnchorEntity(world: .zero)
        arView.scene.anchors.append(scene)

        // 2. Crown Jewel (The Anchor)
        // A heavy, metallic Icosahedron at the center
        let crownJewel = ModelEntity(
            mesh: .generateIcosahedron(radius: 0.3), materials: [createJewelMaterial()])
        crownJewel.position = simd_float3(0, 0, -1)
        crownJewel.name = "CrownJewel"

        // Custom light source coming from the jewel
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

        // 4. Connect Nodes with "Energy Beams"
        connectCluster(nodes: nodes, target: crownJewel, parent: scene)

        // 5. Register System (Normally done globally in App init, but simulated here logic)
        // RealityKit automatically registers systems found in bundle usually, or we manually add if custom
        // For this demo, we assume PressureGraphSystem is registered.
        PressureGraphSystem.registerSystem()

        // Feed reference to system (Static or Singleton access needed in reality, or entity tagging)
        // Here we just ensure components are set.

        // 6. Install Gestures for Interaction
        for nodeAnchor in nodes {
            if let nodeEntity = nodeAnchor.children.first as? ModelEntity {
                // Component for gestures
                nodeEntity.generateCollisionShapes(recursive: true)

                arView.installGestures([.all], for: nodeEntity)
                // Note: RealityKit installGestures handles basic transforms.
                // For custom logic (LongPress), we usually need a UIKit GestureRecognizer on the ARView.
            }
        }

        // Add Camera Control if not in AR
        let camera = PerspectiveCamera()
        camera.look(at: .init(0, 0, -1), from: .init(0, 0, 1), relativeTo: nil)
        let cameraAnchor = AnchorEntity(world: .zero)
        cameraAnchor.addChild(camera)
        arView.scene.anchors.append(cameraAnchor)

        // Manual gesture recognizer for "Remediation" logic
        let longPress = UILongPressGestureRecognizer(
            target: arView, action: #selector(handleLongPress(_:)))
        arView.addGestureRecognizer(longPress)
    }

    // --- ASSET GENERATION HELPERS ---

    func createJewelMaterial() -> SimpleMaterial {
        var mat = SimpleMaterial()
        mat.color = .init(tint: .black)
        mat.metallic = .float(1.0)
        mat.roughness = .float(0.2)
        // Emissive not standard in SimpleMaterial, would use PhysicallyBasedMaterial or Custom
        // For compilation safety in this environment, using SimpleMaterial as placeholder for PBR
        return mat
    }

    func createVulnerabilityMaterial(pressure: Float) -> SimpleMaterial {
        var mat = SimpleMaterial()
        let color = lerpColor(from: .blue, to: .red, t: pressure)
        mat.color = .init(tint: color)
        mat.metallic = .float(0.8)
        mat.roughness = .float(0.4)
        return mat
    }

    func createVulnerabilityCluster(count: Int, target: Entity) -> [AnchorEntity] {
        var anchors: [AnchorEntity] = []

        for i in 0..<count {
            let anchor = AnchorEntity(world: .zero)

            // Position nodes in a sphere around the jewel
            let radius: Float = 1.5
            let theta = Float(i) * 2.0 * .pi / Float(count)
            let phi = acos(1.0 - 2.0 * Float(i) / Float(count))

            let x = radius * sin(phi) * cos(theta)
            let y = radius * sin(phi) * sin(theta)
            let z = radius * cos(phi)

            let position = simd_float3(x, y, z - 1)

            // Generate random initial pressure
            let initialPressure = Float.random(in: 0.3...0.9)

            let mesh = MeshResource.generateBox(size: 0.08)  // Box/Octahedron approx
            let material = createVulnerabilityMaterial(pressure: initialPressure)
            let entity = ModelEntity(mesh: mesh, materials: [material])

            entity.position = position
            entity.look(at: target.position, from: position, relativeTo: nil)
            entity.name = "VulnNode_\(i)"

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

    func connectCluster(nodes: [AnchorEntity], target: Entity, parent: Entity) {
        // Create thin energy beams connecting nodes to the jewel
        for nodeAnchor in nodes {
            guard let node = nodeAnchor.children.first else { continue }

            let dist = distance(node.position, target.position)
            let midpoint = (node.position + target.position) / 2.0

            // Beam Geometry
            let beam = ModelEntity(
                mesh: .generateBox(size: [0.01, 0.01, dist]),
                materials: [UnlitMaterial(color: .cyan)])

            beam.position = midpoint
            beam.look(at: target.position, from: midpoint, relativeTo: nil)

            parent.addChild(beam)
        }
    }

    func lerpColor(from: UIColor, to: UIColor, t: Float) -> UIColor {
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

        return UIColor(red: r, green: g, blue: b, alpha: 1.0)
    }
}

// SwiftUI Integration
struct ARViewContainer<Content: View>: UIViewRepresentable {
    let content: (ARView) -> Content

    init(@ViewBuilder content: @escaping (ARView) -> Content) {
        self.content = content
    }

    func makeUIView(context: Context) -> ARView {
        let arView = ARView(frame: .zero)

        // Enable gestures handling
        return arView
    }

    func updateUIView(_ uiView: ARView, context: Context) {
        // Setup only once
        if uiView.scene.anchors.isEmpty {
            _ = content(uiView)
        }
    }
}

// Extension to handle Long Press since we can't easily put it in struct
extension ARView {
    @objc func handleLongPress(_ sender: UILongPressGestureRecognizer) {
        if sender.state == .began {
            let location = sender.location(in: self)
            if let entity = self.entity(at: location) as? ModelEntity {
                // Remediate
                if var pComp = entity.components[PressureStateComponent.self] {
                    pComp.isFixed = true
                    entity.components[PressureStateComponent.self] = pComp

                    // Visual feedback
                    let animationDef = FromToByAnimation<Transform>(
                        from: entity.transform,
                        to: Transform(
                            scale: .init(0.5, 0.5, 0.5), rotation: entity.transform.rotation,
                            translation: entity.transform.translation),
                        duration: 0.2,
                        bindTarget: .transform
                    )
                    // entity.playAnimation(...) // Helper needed for animation resource
                }
            }
        }
    }
}
