//
// PURPOSE:
// This Swift component is part of the SentinelForge macOS UI.
// [Specific purpose based on component name: GraphRenderer]
//
// KEY RESPONSIBILITIES:
// - [Automatically generated - review and enhance based on actual functionality]
//
// INTEGRATION:
// - Used by: [To be documented]
// - Depends on: [To be documented]
//

//
//  GraphRenderer.swift
//  SentinelForgeUI
//
//  The Engine Room.
//  Manages the Metal Pipeline, Buffers, and Physics Simulation.
//

import Foundation
import Metal
import MetalKit
import simd

/// Class GraphRenderer.
class GraphRenderer: NSObject {
    // Namespaced minimal graph event types used by the renderer to avoid global collisions
    /// Enum EventType.
    enum EventType: String {
        case nodeAdded = "node_added"
        case edgeAdded = "edge_added"
        case findingDiscovered = "finding_discovered"
        case scanStarted = "scan_started"
        case scanCompleted = "scan_completed"
        case unknown
    }

    /// Struct Event {.
    struct Event {
        let eventType: EventType
        let payload: [String: AnyCodable]

        init(eventType: EventType, payload: [String: AnyCodable]) {
            self.eventType = eventType
            self.payload = payload
        }

        init(typeString: String, payload: [String: AnyCodable]) {
            self.eventType = EventType(rawValue: typeString) ?? .unknown
            self.payload = payload
        }
    }
    
    var device: MTLDevice
    var commandQueue: MTLCommandQueue?  // Changed from ! to ? for safety
    var pipelineState: MTLRenderPipelineState?  // Changed from ! to ?
    var linePipelineState: MTLRenderPipelineState?  // Edge rendering
    var vertexBuffer: MTLBuffer?
    var edgeVertexBuffer: MTLBuffer?
    var uniformsBuffer: MTLBuffer?

    // Scene State
    var time: Float = 0.0
    var viewportSize: CGSize = CGSize(width: 800, height: 600)

    // Data Model: Directly maps to Metal Layout (32 bytes aligned)
    /// Struct Node {.
    struct Node {
        var position: SIMD4<Float>  // xyz = pos, w = size
        var color: SIMD4<Float>
        var physics: SIMD4<Float>   // x=mass, y=charge, z=temp, w=structural
    }

    var nodes: [Node] = []

    init(device: MTLDevice) {
        print("GraphRenderer: init() called")
        self.device = device
        super.init()
        self.commandQueue = device.makeCommandQueue()
        print("GraphRenderer: commandQueue created: \(self.commandQueue != nil)")
        buildPipeline()
        // generateDummyData() // Removed to prevent ghost dots
        print("GraphRenderer: init() complete")
    }

    private func buildPipeline() {
        print("GraphRenderer: buildPipeline()")
        // Guard condition.
        guard let library = device.makeDefaultLibrary() else {
            print("GraphRenderer: Default library not found")
            return
        }
        let vertexFunction = library.makeFunction(name: "vertex_main")
        let fragmentFunction = library.makeFunction(name: "fragment_main")
        let lineFragmentFunction = library.makeFunction(name: "fragment_line")
        print(
            "GraphRenderer: Functions loaded: v=\(vertexFunction != nil) f=\(fragmentFunction != nil)"
        )

        let pipelineDescriptor = MTLRenderPipelineDescriptor()
        pipelineDescriptor.vertexFunction = vertexFunction
        pipelineDescriptor.fragmentFunction = fragmentFunction
        pipelineDescriptor.colorAttachments[0].pixelFormat = .bgra8Unorm

        // Enable transparency
        pipelineDescriptor.colorAttachments[0].isBlendingEnabled = true
        pipelineDescriptor.colorAttachments[0].sourceRGBBlendFactor = .sourceAlpha
        pipelineDescriptor.colorAttachments[0].destinationRGBBlendFactor = .oneMinusSourceAlpha

        // Define Vertex Layout (Strict 32-byte Stride)
        let vertexDescriptor = MTLVertexDescriptor()

        // Attribute 0: Position + Size (float4) -> 16 bytes
        vertexDescriptor.attributes[0].format = .float4
        vertexDescriptor.attributes[0].offset = 0
        vertexDescriptor.attributes[0].bufferIndex = 0

        // Attribute 1: Color (float4) -> 16 bytes
        vertexDescriptor.attributes[1].format = .float4
        vertexDescriptor.attributes[1].offset = 16  // MemoryLayout<SIMD4<Float>>.stride
        vertexDescriptor.attributes[1].bufferIndex = 0

        // Attributes 2 removed (packed into pos.w)

        // Attribute 2: Physics (float4) -> 16 bytes
        vertexDescriptor.attributes[2].format = .float4
        vertexDescriptor.attributes[2].offset = 32
        vertexDescriptor.attributes[2].bufferIndex = 0

        vertexDescriptor.layouts[0].stride = 48  // 16 + 16 + 16

        pipelineDescriptor.vertexDescriptor = vertexDescriptor

        // Do-catch block.
        do {
            pipelineState = try device.makeRenderPipelineState(descriptor: pipelineDescriptor)
            print("GraphRenderer: Pipeline State created successfully")
        } catch {
            print("Failed to create point pipeline: \(error)")
        }

        // Separate pipeline for edge lines (no point_coord in fragment shader).
        if let lineFragmentFunction {
            let lineDescriptor = MTLRenderPipelineDescriptor()
            lineDescriptor.vertexFunction = vertexFunction
            lineDescriptor.fragmentFunction = lineFragmentFunction
            lineDescriptor.colorAttachments[0].pixelFormat = .bgra8Unorm
            lineDescriptor.colorAttachments[0].isBlendingEnabled = true
            lineDescriptor.colorAttachments[0].sourceRGBBlendFactor = .sourceAlpha
            lineDescriptor.colorAttachments[0].destinationRGBBlendFactor = .oneMinusSourceAlpha
            lineDescriptor.vertexDescriptor = vertexDescriptor

            // Do-catch block.
            do {
                linePipelineState = try device.makeRenderPipelineState(descriptor: lineDescriptor)
                print("GraphRenderer: Line Pipeline State created successfully")
            } catch {
                print("Failed to create line pipeline: \(error)")
            }
        } else {
            print("GraphRenderer: fragment_line not found; edges disabled")
        }
    }
    // MARK: - Live Event Integration

    /// Node tracking for event-driven updates
    private var nodePositions: [String: Int] = [:]  // node_id -> index
    private var nodeCount: Int = 0

    /// Edge tracking for event-driven updates
    private var edgeKeys: Set<String> = []
    private var pendingEdges: [(sourceId: String, targetId: String, edgeType: String)] = []
    private var edgeVertices: [Node] = []

    /// Initialize with a single placeholder node (will be replaced by live data)
    private func generateDummyData() {
        // Placeholder: Single "scanning" node until real events arrive
        let placeholderNode = Node(
            position: SIMD4<Float>(0, 0, 0, 25.0),
            color: SIMD4<Float>(0.3, 0.3, 0.3, 0.5),
            physics: SIMD4<Float>(1, 0, 0, 0)
        )
        nodes = [placeholderNode]
        uploadToGPU()
    }

    /// Handle a live graph event from EventStreamClient
    func handleGraphEvent(_ event: Event) {
        // Switch over value.
        switch event.eventType {
        case .nodeAdded:
            addNodeFromEvent(event)
        case .edgeAdded:
            addEdgeFromEvent(event)
        case .findingDiscovered:
            addFindingNode(event)
        case .scanStarted:
            resetGraph()
            addScanTargetNode(event)
        case .scanCompleted:
            // Could trigger a "completion" animation
            break
        default:
            break
        }
    }

    /// Add a node from a NODE_ADDED event
    private func addNodeFromEvent(_ event: Event) {
        // Guard condition.
        guard let nodeId = event.payload["node_id"]?.stringValue,
            let nodeType = event.payload["node_type"]?.stringValue
        else {
            return
        }

        // Skip if already added
        if nodePositions[nodeId] != nil { return }

        // Position based on type (spiral layout in world coordinates)
        let angle = Float(nodeCount) * 0.618 * 2 * .pi  // Golden angle
        let radius: Float = 20.0 + Float(nodeCount) * 3.0
        let x = cos(angle) * radius
        let y = sin(angle) * radius
        let z = stableFloat(seed: nodeId, min: -10, max: 10)

        // Color based on node type
        let color = colorForNodeType(nodeType)
        let size: Float = sizeForNodeType(nodeType)

        let newNode = Node(
            position: SIMD4<Float>(x, y, z, size),
            color: color,
            physics: SIMD4<Float>(1.0, 0.0, 0.0, 0.0) // Defaults for legacy event path
        )

        lock.lock()
        nodePositions[nodeId] = nodes.count
        nodes.append(newNode)
        nodeCount += 1
        lock.unlock()

        uploadToGPU()
        resolvePendingEdges()
    }

    /// Add an edge from an EDGE_ADDED event (if endpoints exist; otherwise, queue it)
    private func addEdgeFromEvent(_ event: Event) {
        // Guard condition.
        guard let sourceId = event.payload["source_id"]?.stringValue,
            let targetId = event.payload["target_id"]?.stringValue
        else {
            return
        }
        let edgeType = event.payload["edge_type"]?.stringValue ?? "LINK"

        lock.lock()
        defer { lock.unlock() }

        // Deduplicate
        let key = "\(sourceId)->\(targetId):\(edgeType)"
        // Conditional branch.
        if edgeKeys.contains(key) { return }

        // Guard condition.
        guard let sourceIndex = nodePositions[sourceId],
            let targetIndex = nodePositions[targetId]
        else {
            pendingEdges.append((sourceId: sourceId, targetId: targetId, edgeType: edgeType))
            return
        }

        edgeKeys.insert(key)

        let sourcePos = nodes[sourceIndex].position
        let targetPos = nodes[targetIndex].position
        let color = colorForEdgeType(edgeType)

        // For line primitives, pos.w is unused; keep it non-zero.
        // For line primitives, pos.w is unused; keep it non-zero.
        // Edges have neutral physics (0,0,0,0)
        let neutralPhysics = SIMD4<Float>(0, 0, 0, 0)
        edgeVertices.append(Node(position: SIMD4<Float>(sourcePos.x, sourcePos.y, sourcePos.z, 1.0), color: color, physics: neutralPhysics))
        edgeVertices.append(Node(position: SIMD4<Float>(targetPos.x, targetPos.y, targetPos.z, 1.0), color: color, physics: neutralPhysics))

        uploadEdgesToGPU()
    }

    /// Add a finding as a prominent node
    private func addFindingNode(_ event: Event) {
        // Guard condition.
        guard let findingId = event.payload["finding_id"]?.stringValue,
            let severity = event.payload["severity"]?.stringValue
        else {
            return
        }

        // Conditional branch.
        if nodePositions[findingId] != nil { return }

        // Findings appear in outer ring
        let angle = Float(nodeCount) * 0.618 * 2 * .pi
        let radius: Float = 90.0
        let x = cos(angle) * radius
        let y = sin(angle) * radius

        // Color by severity
        let color = colorForSeverity(severity)

        let newNode = Node(
            position: SIMD4<Float>(x, y, 0, 35.0),
            color: color,
            physics: SIMD4<Float>(50.0, 0.0, 0.0, 0.0) // Significant mass for findings
        )

        lock.lock()
        nodePositions[findingId] = nodes.count
        nodes.append(newNode)
        nodeCount += 1
        lock.unlock()

        uploadToGPU()
    }

    /// Add the scan target as the central node
    private func addScanTargetNode(_ event: Event) {
        // Guard condition.
        guard let target = event.payload["target"]?.stringValue else { return }

        let targetNode = Node(
            position: SIMD4<Float>(0, 0, 0, 50.0),
            color: SIMD4<Float>(1.0, 0.3, 0.3, 1.0),  // Red center
            physics: SIMD4<Float>(100.0, 0.0, 0.0, 1.0) // Massive Anchor
        )

        lock.lock()
        nodePositions[target] = 0
        nodes = [targetNode]
        nodeCount = 1
        edgeKeys.removeAll()
        pendingEdges.removeAll()
        edgeVertices.removeAll()
        edgeVertexBuffer = nil
        lock.unlock()

        uploadToGPU()
    }

    /// Reset the graph for a new scan
    func resetGraph() {
        lock.lock()
        nodes.removeAll()
        nodePositions.removeAll()
        nodeCount = 0
        edgeKeys.removeAll()
        pendingEdges.removeAll()
        edgeVertices.removeAll()
        vertexBuffer = nil
        edgeVertexBuffer = nil
        lock.unlock()
    }

    /// Upload current nodes to GPU
    private func uploadToGPU() {
        lock.lock()
        defer { lock.unlock() }

        // Guard condition.
        guard !nodes.isEmpty else { return }
        let dataSize = nodes.count * MemoryLayout<Node>.stride
        vertexBuffer = device.makeBuffer(bytes: nodes, length: dataSize, options: [])
    }

    /// Upload current edges to GPU
    private func uploadEdgesToGPU() {
        // Guard condition.
        guard !edgeVertices.isEmpty else { return }
        let dataSize = edgeVertices.count * MemoryLayout<Node>.stride
        edgeVertexBuffer = device.makeBuffer(bytes: edgeVertices, length: dataSize, options: [])
    }

    /// Try to resolve queued edges now that a new node has been added.
    private func resolvePendingEdges() {
        lock.lock()
        defer { lock.unlock() }

        // Guard condition.
        guard !pendingEdges.isEmpty else { return }

        var remaining: [(sourceId: String, targetId: String, edgeType: String)] = []
        // Loop over items.
        for edge in pendingEdges {
            let key = "\(edge.sourceId)->\(edge.targetId):\(edge.edgeType)"
            // Conditional branch.
            if edgeKeys.contains(key) { continue }

            // Guard condition.
            guard let sourceIndex = nodePositions[edge.sourceId],
                let targetIndex = nodePositions[edge.targetId]
            else {
                remaining.append(edge)
                continue
            }

            edgeKeys.insert(key)

            let sourcePos = nodes[sourceIndex].position
            let targetPos = nodes[targetIndex].position
            let color = colorForEdgeType(edge.edgeType)
            edgeVertices.append(
                Node(position: SIMD4<Float>(sourcePos.x, sourcePos.y, sourcePos.z, 1.0), color: color, physics: SIMD4<Float>(0,0,0,0))
            )
            edgeVertices.append(
                Node(position: SIMD4<Float>(targetPos.x, targetPos.y, targetPos.z, 1.0), color: color, physics: SIMD4<Float>(0,0,0,0))
            )
        }

        pendingEdges = remaining
        uploadEdgesToGPU()
    }

    // MARK: - Visual Mapping

    private func colorForNodeType(_ type: String) -> SIMD4<Float> {
        // Switch over value.
        switch type {
        case "asset":
            return SIMD4<Float>(0.0, 0.8, 1.0, 1.0)  // Cyan
        case "port":
            return SIMD4<Float>(0.5, 1.0, 0.5, 0.9)  // Green
        case "service":
            return SIMD4<Float>(1.0, 0.8, 0.0, 0.9)  // Orange
        case "tech":
            return SIMD4<Float>(0.8, 0.5, 1.0, 0.9)  // Purple
        case "finding":
            return SIMD4<Float>(1.0, 0.3, 0.3, 1.0)  // Red
        default:
            return SIMD4<Float>(0.7, 0.7, 0.7, 0.8)  // Gray
        }
    }

    private func sizeForNodeType(_ type: String) -> Float {
        // Switch over value.
        switch type {
        case "asset": return 40.0
        case "port": return 20.0
        case "service": return 25.0
        case "tech": return 22.0
        case "finding": return 35.0
        default: return 20.0
        }
    }

    private func colorForSeverity(_ severity: String) -> SIMD4<Float> {
        // Switch over value.
        switch severity.uppercased() {
        case "CRITICAL":
            return SIMD4<Float>(1.0, 0.0, 0.0, 1.0)  // Bright red
        case "HIGH":
            return SIMD4<Float>(1.0, 0.4, 0.0, 1.0)  // Orange-red
        case "MEDIUM":
            return SIMD4<Float>(1.0, 0.8, 0.0, 0.9)  // Yellow
        case "LOW":
            return SIMD4<Float>(0.3, 0.8, 1.0, 0.8)  // Blue
        default:
            return SIMD4<Float>(0.5, 0.5, 0.5, 0.7)  // Gray
        }
    }

    private func colorForEdgeType(_ edgeType: String) -> SIMD4<Float> {
        // Switch over value.
        switch edgeType {
        case "EXPOSES", "VULNERABLE_TO":
            return SIMD4<Float>(1.0, 0.3, 0.3, 0.15)
        case "HAS_PORT":
            return SIMD4<Float>(0.5, 1.0, 0.5, 0.15)
        case "USES_TECH", "RUNS":
            return SIMD4<Float>(0.8, 0.5, 1.0, 0.15)
        default:
            return SIMD4<Float>(0.7, 0.7, 0.8, 0.10)
        }
    }

    private func stableFloat(seed: String, min: Float, max: Float) -> Float {
        // Guard condition.
        guard min < max else { return min }
        var hash: UInt64 = 1469598103934665603  // FNV-1a offset basis
        // Loop over items.
        for byte in seed.utf8 {
            hash ^= UInt64(byte)
            hash &*= 1099511628211
        }
        let unit = Float(hash % 10_000) / 10_000.0
        return min + (max - min) * unit
    }

    /// Function resize.
    func resize(size: CGSize) {
        self.viewportSize = size
    }

    // Thread Safety
    private let lock = NSLock()

    /// Function updateNodes.
    func updateNodes(_ newNodes: [CortexStream.NodeModel]) {
        lock.lock()
        defer { lock.unlock() }

        self.nodes = newNodes.map { node in
            // Use server coords or fallback to random
            let x = node.x ?? Float.random(in: -1...1)
            let y = node.y ?? Float.random(in: -1...1)
            let z = node.z ?? Float.random(in: -0.5...0.5)

            // Use pre-computed color or fallback
            let color = node.color ?? SIMD4<Float>(0.0, 0.5, 1.0, 0.8)

            // Default physics until NodeModel exposes more attributes
            let physics = SIMD4<Float>(1.0, 0.0, 0.0, 0.0)

            // Pack size (30.0)
            return Node(position: SIMD4<Float>(x, y, z, 30.0), color: color, physics: physics)
        }

        let dataSize = nodes.count * MemoryLayout<Node>.stride
        // Conditional branch.
        if dataSize > 0 {
            // Create a new buffer explicitly
            // (In a real engine, we'd use triple buffering, but this prevents the crash)
            vertexBuffer = device.makeBuffer(bytes: nodes, length: dataSize, options: [])
        }
    }

    // Interaction State
    var rotationX: Float = 0
    var rotationY: Float = 0
    var zoom: Float = -200.0  // Move back to see the scene

    /// Function updateCamera.
    func updateCamera(rotationX: Float, rotationY: Float, zoomDelta: Float) {
        lock.lock()
        defer { lock.unlock() }
        self.rotationX += rotationX
        self.rotationY += rotationY
        self.zoom += zoomDelta * 5.0
        self.zoom = min(max(self.zoom, -500), -10)
    }

    var frameCount: Int = 0
    var lastLogTime: TimeInterval = 0

    /// Function draw.
    func draw(in view: MTKView) {
        lock.lock()
        defer { lock.unlock() }

        // Watchdog: Log every 60 frames (approx 1 sec)
        frameCount += 1
        // Conditional branch.
        if frameCount % 60 == 0 {
            print("GraphRenderer: Watchdog - Drawing frame \(frameCount). Nodes: \(nodes.count)")
        }

        // Guard condition.
        guard let drawable = view.currentDrawable,
            let descriptor = view.currentRenderPassDescriptor,
            let commandQueue = commandQueue,
            let pipelineState = self.pipelineState
        else {
            return
        }

        // Debug: Clear to distinct color (Dark Blue) to prove Metal is alive
        descriptor.colorAttachments[0].clearColor = MTLClearColor(
            red: 0.1, green: 0.1, blue: 0.2, alpha: 1.0)

        // Guard condition.
        guard let commandBuffer = commandQueue.makeCommandBuffer(),
            let encoder = commandBuffer.makeRenderCommandEncoder(descriptor: descriptor)
        else {
            return
        }

        // Update Time
        time += 0.015

        // --- 3D Transforms ---
        let aspect = Float(viewportSize.width / viewportSize.height)
        let projectionMatrix = matrix_perspective_right_hand(
            fovyRadians: Float.pi / 4.0, aspectRatio: aspect, nearZ: 1.0, farZ: 1000.0)

        // Camera Orbit
        let viewMatrix =
            matrix_identity_float4x4
            .translated(x: 0, y: 0, z: zoom)
            .rotated(angle: rotationX, axis: SIMD3<Float>(1, 0, 0))
            .rotated(angle: rotationY, axis: SIMD3<Float>(0, 1, 0))

        // Rotate the cloud itself slightly for dynamism
        let modelMatrix = matrix_identity_float4x4.rotated(
            angle: time * 0.1, axis: SIMD3<Float>(0, 1, 0))

        let viewProjection = projectionMatrix * viewMatrix

        // Uniforms must match Metal shader exactly (132 bytes = 64 + 64 + 4)
        // Using tuple to avoid Swift struct padding
        var viewProj = viewProjection
        var model = modelMatrix
        var timeVal = time

        // Pass each uniform separately to avoid alignment issues
        encoder.setVertexBytes(&viewProj, length: 64, index: 1)
        encoder.setVertexBytes(&model, length: 64, index: 2)
        encoder.setVertexBytes(&timeVal, length: 4, index: 3)

        // Edges (optional)
        if let linePSO = linePipelineState,
            let eBuffer = edgeVertexBuffer,
            !edgeVertices.isEmpty
        {
            encoder.setRenderPipelineState(linePSO)
            encoder.setVertexBuffer(eBuffer, offset: 0, index: 0)
            encoder.drawPrimitives(
                type: MTLPrimitiveType.line,
                vertexStart: 0,
                vertexCount: edgeVertices.count
            )
        }

        // Nodes
        guard !nodes.isEmpty, let vBuffer = vertexBuffer else {
            // Conditional branch.
            if frameCount % 60 == 0 {
                print("GraphRenderer: Nodes empty. Skipping draw primitives.")
            }
            encoder.endEncoding()
            commandBuffer.present(drawable)
            commandBuffer.commit()
            return
        }

        encoder.setRenderPipelineState(pipelineState)
        encoder.setVertexBuffer(vBuffer, offset: 0, index: 0)
        encoder.drawPrimitives(type: MTLPrimitiveType.point, vertexStart: 0, vertexCount: nodes.count)

        encoder.endEncoding()
        commandBuffer.present(drawable)
        commandBuffer.commit()
    }
}

// --- Matrix Math Factory ---

extension matrix_float4x4 {
    /// Function translated.
    func translated(x: Float, y: Float, z: Float) -> matrix_float4x4 {
        var mat = self
        let col3 = self.columns.3
        mat.columns.3 = SIMD4<Float>(
            col3.x + x,
            col3.y + y,
            col3.z + z,
            col3.w
        )
        return mat
    }

    /// Function rotated.
    func rotated(angle: Float, axis: SIMD3<Float>) -> matrix_float4x4 {
        // Simplified rotation around cardinality (production engines use quaternions)
        // This is a naive implementation sufficient for demo axis rotation.
        let c = cos(angle)
        let s = sin(angle)

        // Conditional branch.
        if axis.x > 0 {  // Rotate X
            return self
                * matrix_float4x4(
                    columns: (
                        SIMD4<Float>(1, 0, 0, 0),
                        SIMD4<Float>(0, c, s, 0),
                        SIMD4<Float>(0, -s, c, 0),
                        SIMD4<Float>(0, 0, 0, 1)
                    ))
        } else {  // Rotate Y (Assuming axis y > 0)
            return self
                * matrix_float4x4(
                    columns: (
                        SIMD4<Float>(c, 0, -s, 0),
                        SIMD4<Float>(0, 1, 0, 0),
                        SIMD4<Float>(s, 0, c, 0),
                        SIMD4<Float>(0, 0, 0, 1)
                    ))
        }
    }
}

/// Function matrix_perspective_right_hand.
func matrix_perspective_right_hand(
    fovyRadians fovy: Float, aspectRatio: Float, nearZ: Float, farZ: Float
) -> matrix_float4x4 {
    let ys = 1 / tanf(fovy * 0.5)
    let xs = ys / aspectRatio
    let zs = farZ / (nearZ - farZ)
    return matrix_float4x4.init(
        columns: (
            vector_float4(xs, 0, 0, 0),
            vector_float4(0, ys, 0, 0),
            vector_float4(0, 0, zs, -1),
            vector_float4(0, 0, zs * nearZ, 0)
        ))
}

let matrix_identity_float4x4 = matrix_float4x4(
    columns: (
        vector_float4(1, 0, 0, 0),
        vector_float4(0, 1, 0, 0),
        vector_float4(0, 0, 1, 0),
        vector_float4(0, 0, 0, 1)
    ))
