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
final class GraphRenderer: NSObject {

    // Namespaced minimal graph event types used by the renderer to avoid global collisions
    enum EventType: String {
        case nodeAdded = "node_added"
        case edgeAdded = "edge_added"
        case findingDiscovered = "finding_discovered"
        case scanStarted = "scan_started"
        case scanCompleted = "scan_completed"
        case unknown
    }

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

    // MARK: - Metal Core

    let device: MTLDevice
    private(set) var commandQueue: MTLCommandQueue?
    private(set) var pipelineState: MTLRenderPipelineState?
    private(set) var linePipelineState: MTLRenderPipelineState?
    private(set) var depthState: MTLDepthStencilState?
    private(set) var edgeDepthState: MTLDepthStencilState?

    private(set) var vertexBuffer: MTLBuffer?
    private(set) var edgeVertexBuffer: MTLBuffer?

    // MARK: - Scene State

    private var time: Float = 0.0
    private var viewportSize: CGSize = CGSize(width: 800, height: 600)

    // Interaction State
    var rotationX: Float = 0
    var rotationY: Float = 0
    var zoom: Float = -120.0  // Closer camera for dramatic depth

    // Thread Safety
    private let lock = NSLock()

    // MARK: - Data Model

    /// Data Model: Directly maps to Metal Layout (48 bytes)
    struct Node {
        var position: SIMD4<Float>  // xyz = pos, w = size
        var color: SIMD4<Float>
        var physics: SIMD4<Float>  // x=mass, y=charge, z=temp, w=structural
    }

    private var nodes: [Node] = []

    /// Uniforms must match Metal shader exactly.
    /// Keep this tightly packed and explicit.
    struct Uniforms {
        var viewProj: matrix_float4x4  // 64
        var model: matrix_float4x4  // 64
        var time: Float  // 4
        var _pad0: SIMD3<Float>  // 12 (pad to 16-byte alignment)
        // total = 144 bytes
    }

    // MARK: - Live Event Integration

    private var nodePositions: [String: Int] = [:]  // node_id -> index
    private var nodeCount: Int = 0

    private var edgeKeys: Set<String> = []
    private var pendingEdges: [(sourceId: String, targetId: String, edgeType: String)] = []
    private var edgeVertices: [Node] = []

    // MARK: - Init

    init(device: MTLDevice) {
        print("GraphRenderer: init() called")
        self.device = device
        super.init()
        self.commandQueue = device.makeCommandQueue()
        print("GraphRenderer: commandQueue created: \(self.commandQueue != nil)")
        buildPipeline()
        buildDepthState()
        print("GraphRenderer: init() complete")
    }

    // MARK: - Public Helpers

    /// Call this from wherever you create/configure the MTKView.
    /// Without a depth format, you will never get real 3D occlusion.
    func configure(view: MTKView) {
        view.device = device
        view.colorPixelFormat = .bgra8Unorm
        view.depthStencilPixelFormat = .depth32Float
        view.sampleCount = 1
        view.clearDepth = 1.0
        view.isPaused = false
        view.enableSetNeedsDisplay = false
    }

    func resize(size: CGSize) {
        viewportSize = size
    }

    func updateCamera(rotationX: Float, rotationY: Float, zoomDelta: Float) {
        lock.lock()
        defer { lock.unlock() }
        self.rotationX += rotationX
        self.rotationY += rotationY
        self.zoom += zoomDelta * 5.0
        self.zoom = min(max(self.zoom, -500), -10)
    }

    // MARK: - Pipeline / Depth

    private func buildPipeline() {
        print("GraphRenderer: buildPipeline()")

        guard let library = device.makeDefaultLibrary() else {
            print("GraphRenderer: Default library not found")
            return
        }

        let vertexFunction = library.makeFunction(name: "vertex_main")
        let fragmentFunction = library.makeFunction(name: "fragment_main")
        let lineFragmentFunction = library.makeFunction(name: "fragment_line")

        print(
            "GraphRenderer: Functions loaded: v=\(vertexFunction != nil) f=\(fragmentFunction != nil) lineF=\(lineFragmentFunction != nil)"
        )

        // Vertex Layout (48 bytes stride)
        let vertexDescriptor = MTLVertexDescriptor()

        // Attribute 0: Position + Size (float4) -> 16 bytes
        vertexDescriptor.attributes[0].format = .float4
        vertexDescriptor.attributes[0].offset = 0
        vertexDescriptor.attributes[0].bufferIndex = 0

        // Attribute 1: Color (float4) -> 16 bytes
        vertexDescriptor.attributes[1].format = .float4
        vertexDescriptor.attributes[1].offset = 16
        vertexDescriptor.attributes[1].bufferIndex = 0

        // Attribute 2: Physics (float4) -> 16 bytes
        vertexDescriptor.attributes[2].format = .float4
        vertexDescriptor.attributes[2].offset = 32
        vertexDescriptor.attributes[2].bufferIndex = 0

        vertexDescriptor.layouts[0].stride = 48

        // Points pipeline
        let pipelineDescriptor = MTLRenderPipelineDescriptor()
        pipelineDescriptor.vertexFunction = vertexFunction
        pipelineDescriptor.fragmentFunction = fragmentFunction
        pipelineDescriptor.vertexDescriptor = vertexDescriptor
        pipelineDescriptor.colorAttachments[0].pixelFormat = .bgra8Unorm

        // Depth must match MTKView.depthStencilPixelFormat
        pipelineDescriptor.depthAttachmentPixelFormat = .depth32Float

        // Transparency
        pipelineDescriptor.colorAttachments[0].isBlendingEnabled = true
        pipelineDescriptor.colorAttachments[0].sourceRGBBlendFactor = .sourceAlpha
        pipelineDescriptor.colorAttachments[0].destinationRGBBlendFactor = .oneMinusSourceAlpha
        pipelineDescriptor.colorAttachments[0].sourceAlphaBlendFactor = .sourceAlpha
        pipelineDescriptor.colorAttachments[0].destinationAlphaBlendFactor = .oneMinusSourceAlpha

        do {
            pipelineState = try device.makeRenderPipelineState(descriptor: pipelineDescriptor)
            print("GraphRenderer: Point Pipeline State created successfully")
        } catch {
            print("Failed to create point pipeline: \(error)")
        }

        // Lines pipeline
        if let lineFragmentFunction {
            let lineDescriptor = MTLRenderPipelineDescriptor()
            lineDescriptor.vertexFunction = vertexFunction
            lineDescriptor.fragmentFunction = lineFragmentFunction
            lineDescriptor.vertexDescriptor = vertexDescriptor
            lineDescriptor.colorAttachments[0].pixelFormat = .bgra8Unorm
            lineDescriptor.depthAttachmentPixelFormat = .depth32Float

            lineDescriptor.colorAttachments[0].isBlendingEnabled = true
            lineDescriptor.colorAttachments[0].sourceRGBBlendFactor = .sourceAlpha
            lineDescriptor.colorAttachments[0].destinationRGBBlendFactor = .oneMinusSourceAlpha
            lineDescriptor.colorAttachments[0].sourceAlphaBlendFactor = .sourceAlpha
            lineDescriptor.colorAttachments[0].destinationAlphaBlendFactor = .oneMinusSourceAlpha

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

    private func buildDepthState() {
        // Standard Depth State (Nodes)
        let desc = MTLDepthStencilDescriptor()
        desc.isDepthWriteEnabled = true
        desc.depthCompareFunction = .less
        depthState = device.makeDepthStencilState(descriptor: desc)

        // Edge Depth State (Read-only)
        // Edges should test against nodes but not occlude them or each other
        let edgeDesc = MTLDepthStencilDescriptor()
        edgeDesc.isDepthWriteEnabled = false
        edgeDesc.depthCompareFunction = .less
        edgeDepthState = device.makeDepthStencilState(descriptor: edgeDesc)
    }

    // MARK: - Event Handling

    func handleGraphEvent(_ event: Event) {
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
            break
        default:
            break
        }
    }

    private func addNodeFromEvent(_ event: Event) {
        guard let nodeId = event.payload["node_id"]?.stringValue,
            let nodeType = event.payload["node_type"]?.stringValue
        else { return }

        if nodePositions[nodeId] != nil { return }

        let angle = Float(nodeCount) * 0.618 * 2 * .pi
        let radius: Float = 20.0 + Float(nodeCount) * 3.0
        let x = cos(angle) * radius
        let y = sin(angle) * radius
        // Dramatic Z-spread for parallax
        let z = stableFloat(seed: nodeId, min: -120, max: 120)

        let color = colorForNodeType(nodeType)
        let size: Float = sizeForNodeType(nodeType)

        let newNode = Node(
            position: SIMD4<Float>(x, y, z, size),
            color: color,
            physics: SIMD4<Float>(1.0, 0.0, 0.0, 0.0)
        )

        lock.lock()
        nodePositions[nodeId] = nodes.count
        nodes.append(newNode)
        nodeCount += 1
        lock.unlock()

        uploadToGPU()
        resolvePendingEdges()
    }

    private func addEdgeFromEvent(_ event: Event) {
        guard let sourceId = event.payload["source_id"]?.stringValue,
            let targetId = event.payload["target_id"]?.stringValue
        else { return }

        let edgeType = event.payload["edge_type"]?.stringValue ?? "LINK"

        lock.lock()
        defer { lock.unlock() }

        let key = "\(sourceId)->\(targetId):\(edgeType)"
        if edgeKeys.contains(key) { return }

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

        let neutralPhysics = SIMD4<Float>(0, 0, 0, 0)

        edgeVertices.append(
            Node(
                position: SIMD4<Float>(sourcePos.x, sourcePos.y, sourcePos.z, 1.0), color: color,
                physics: neutralPhysics))
        edgeVertices.append(
            Node(
                position: SIMD4<Float>(targetPos.x, targetPos.y, targetPos.z, 1.0), color: color,
                physics: neutralPhysics))

        uploadEdgesToGPU()
    }

    private func addFindingNode(_ event: Event) {
        guard let findingId = event.payload["finding_id"]?.stringValue,
            let severity = event.payload["severity"]?.stringValue
        else { return }

        if nodePositions[findingId] != nil { return }

        let angle = Float(nodeCount) * 0.618 * 2 * .pi
        let radius: Float = 90.0
        let x = cos(angle) * radius
        let y = sin(angle) * radius
        let z = stableFloat(seed: findingId, min: -40, max: 40)

        let color = colorForSeverity(severity)

        let newNode = Node(
            position: SIMD4<Float>(x, y, z, 35.0),
            color: color,
            physics: SIMD4<Float>(50.0, 0.0, 0.0, 0.0)
        )

        lock.lock()
        nodePositions[findingId] = nodes.count
        nodes.append(newNode)
        nodeCount += 1
        lock.unlock()

        uploadToGPU()
    }

    private func addScanTargetNode(_ event: Event) {
        guard let target = event.payload["target"]?.stringValue else { return }

        let targetNode = Node(
            position: SIMD4<Float>(0, 0, 0, 50.0),
            color: SIMD4<Float>(1.0, 0.3, 0.3, 1.0),
            physics: SIMD4<Float>(100.0, 0.0, 0.0, 1.0)
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

    // MARK: - GPU Upload

    private func uploadToGPU() {
        lock.lock()
        defer { lock.unlock() }

        guard !nodes.isEmpty else { return }
        let dataSize = nodes.count * MemoryLayout<Node>.stride
        vertexBuffer = device.makeBuffer(bytes: nodes, length: dataSize, options: [])
    }

    private func uploadEdgesToGPU() {
        guard !edgeVertices.isEmpty else { return }
        let dataSize = edgeVertices.count * MemoryLayout<Node>.stride
        edgeVertexBuffer = device.makeBuffer(bytes: edgeVertices, length: dataSize, options: [])
    }

    private func resolvePendingEdges() {
        lock.lock()
        defer { lock.unlock() }

        guard !pendingEdges.isEmpty else { return }

        var remaining: [(sourceId: String, targetId: String, edgeType: String)] = []

        for edge in pendingEdges {
            let key = "\(edge.sourceId)->\(edge.targetId):\(edge.edgeType)"
            if edgeKeys.contains(key) { continue }

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
                Node(
                    position: SIMD4<Float>(sourcePos.x, sourcePos.y, sourcePos.z, 1.0),
                    color: color, physics: SIMD4<Float>(0, 0, 0, 0)))
            edgeVertices.append(
                Node(
                    position: SIMD4<Float>(targetPos.x, targetPos.y, targetPos.z, 1.0),
                    color: color, physics: SIMD4<Float>(0, 0, 0, 0)))
        }

        pendingEdges = remaining
        uploadEdgesToGPU()
    }

    // MARK: - Visual Mapping

    private func colorForNodeType(_ type: String) -> SIMD4<Float> {
        switch type {
        case "asset": return SIMD4<Float>(0.0, 0.8, 1.0, 1.0)
        case "port": return SIMD4<Float>(0.5, 1.0, 0.5, 0.9)
        case "service": return SIMD4<Float>(1.0, 0.8, 0.0, 0.9)
        case "tech": return SIMD4<Float>(0.8, 0.5, 1.0, 0.9)
        case "finding": return SIMD4<Float>(1.0, 0.3, 0.3, 1.0)
        default: return SIMD4<Float>(0.7, 0.7, 0.7, 0.8)
        }
    }

    private func sizeForNodeType(_ type: String) -> Float {
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
        switch severity.uppercased() {
        case "CRITICAL": return SIMD4<Float>(1.0, 0.0, 0.0, 1.0)
        case "HIGH": return SIMD4<Float>(1.0, 0.4, 0.0, 1.0)
        case "MEDIUM": return SIMD4<Float>(1.0, 0.8, 0.0, 0.9)
        case "LOW": return SIMD4<Float>(0.3, 0.8, 1.0, 0.8)
        default: return SIMD4<Float>(0.5, 0.5, 0.5, 0.7)
        }
    }

    private func colorForEdgeType(_ edgeType: String) -> SIMD4<Float> {
        switch edgeType {
        case "EXPOSES", "VULNERABLE_TO": return SIMD4<Float>(1.0, 0.3, 0.3, 0.15)
        case "HAS_PORT": return SIMD4<Float>(0.5, 1.0, 0.5, 0.15)
        case "USES_TECH", "RUNS": return SIMD4<Float>(0.8, 0.5, 1.0, 0.15)
        default: return SIMD4<Float>(0.7, 0.7, 0.8, 0.10)
        }
    }

    private func stableFloat(seed: String, min: Float, max: Float) -> Float {
        guard min < max else { return min }
        var hash: UInt64 = 1_469_598_103_934_665_603  // FNV-1a offset basis
        for byte in seed.utf8 {
            hash ^= UInt64(byte)
            hash &*= 1_099_511_628_211
        }
        let unit = Float(hash % 10_000) / 10_000.0
        return min + (max - min) * unit
    }

    // MARK: - External Node Update

    func updateNodes(_ newNodes: [CortexStream.NodeModel]) {
        lock.lock()
        defer { lock.unlock() }

        self.nodes = newNodes.map { node in
            let x = node.x ?? Float.random(in: -40...40)
            let y = node.y ?? Float.random(in: -40...40)
            let z = node.z ?? Float.random(in: -120...120)

            let color = node.color ?? SIMD4<Float>(0.0, 0.5, 1.0, 0.8)
            let physics = SIMD4<Float>(1.0, 0.0, 0.0, 0.0)

            return Node(position: SIMD4<Float>(x, y, z, 30.0), color: color, physics: physics)
        }

        let dataSize = nodes.count * MemoryLayout<Node>.stride
        if dataSize > 0 {
            vertexBuffer = device.makeBuffer(bytes: nodes, length: dataSize, options: [])
        }
    }

    // MARK: - Draw

    private var frameCount: Int = 0

    func draw(in view: MTKView) {
        lock.lock()
        defer { lock.unlock() }

        frameCount += 1
        if frameCount % 60 == 0 {
            print(
                "GraphRenderer: Watchdog - Drawing frame \(frameCount). Nodes: \(nodes.count) Edges: \(edgeVertices.count)"
            )
        }

        guard let drawable = view.currentDrawable,
            let descriptor = view.currentRenderPassDescriptor,
            let commandQueue = commandQueue,
            let pipelineState = pipelineState
        else {
            return
        }

        // Clear
        descriptor.colorAttachments[0].clearColor = MTLClearColor(
            red: 0.1, green: 0.1, blue: 0.2, alpha: 1.0)
        descriptor.depthAttachment.clearDepth = 1.0
        descriptor.depthAttachment.loadAction = .clear
        descriptor.depthAttachment.storeAction = .dontCare

        guard let commandBuffer = commandQueue.makeCommandBuffer(),
            let encoder = commandBuffer.makeRenderCommandEncoder(descriptor: descriptor)
        else {
            return
        }

        // Depth state ON (this is what makes it feel 3D)
        if let depthState {
            encoder.setDepthStencilState(depthState)
        }

        time += 0.015

        let aspect = Float(viewportSize.width / max(1.0, viewportSize.height))
        let projectionMatrix = matrix_perspective_right_hand(
            fovyRadians: Float.pi / 4.0,
            aspectRatio: aspect,
            nearZ: 1.0,
            farZ: 1000.0
        )

        // Camera
        let viewMatrix =
            matrix_identity_float4x4
            .translated(x: 0, y: 0, z: zoom)
            .rotated(angle: rotationX, axis: SIMD3<Float>(1, 0, 0))
            .rotated(angle: rotationY, axis: SIMD3<Float>(0, 1, 0))

        // Compound rotation for complex motion parallax
        let modelMatrix =
            matrix_identity_float4x4
            .rotated(angle: time * 0.12, axis: SIMD3<Float>(0, 1, 0))
            .rotated(angle: time * 0.07, axis: SIMD3<Float>(1, 0, 0))

        let viewProjection = projectionMatrix * viewMatrix

        var uniforms = Uniforms(
            viewProj: viewProjection, model: modelMatrix, time: time, _pad0: SIMD3<Float>(0, 0, 0))
        encoder.setVertexBytes(&uniforms, length: MemoryLayout<Uniforms>.stride, index: 1)

        // Edges
        if let linePSO = linePipelineState,
            let eBuffer = edgeVertexBuffer,
            !edgeVertices.isEmpty
        {
            // Use Read-Only Depth for edges (transparency-like behavior)
            if let edgeDS = edgeDepthState {
                encoder.setDepthStencilState(edgeDS)
            }

            encoder.setRenderPipelineState(linePSO)
            encoder.setVertexBuffer(eBuffer, offset: 0, index: 0)
            encoder.drawPrimitives(type: .line, vertexStart: 0, vertexCount: edgeVertices.count)
        }

        // Restore write-enabled depth for Nodes
        if let depthState {
            encoder.setDepthStencilState(depthState)
        }

        // Nodes
        guard !nodes.isEmpty, let vBuffer = vertexBuffer else {
            if frameCount % 60 == 0 { print("GraphRenderer: Nodes empty. Skipping draw.") }
            encoder.endEncoding()
            commandBuffer.present(drawable)
            commandBuffer.commit()
            return
        }

        encoder.setRenderPipelineState(pipelineState)
        encoder.setVertexBuffer(vBuffer, offset: 0, index: 0)
        encoder.drawPrimitives(type: .point, vertexStart: 0, vertexCount: nodes.count)

        encoder.endEncoding()
        commandBuffer.present(drawable)
        commandBuffer.commit()
    }
}

// MARK: - Matrix Math

extension matrix_float4x4 {

    func translated(x: Float, y: Float, z: Float) -> matrix_float4x4 {
        let t = matrix_float4x4(
            columns: (
                SIMD4<Float>(1, 0, 0, 0),
                SIMD4<Float>(0, 1, 0, 0),
                SIMD4<Float>(0, 0, 1, 0),
                SIMD4<Float>(x, y, z, 1)
            ))
        return self * t
    }

    func rotated(angle: Float, axis: SIMD3<Float>) -> matrix_float4x4 {
        let a = simd_normalize(axis)
        let c = cos(angle)
        let s = sin(angle)
        let t = 1 - c

        // Rodrigues' rotation formula
        let r = matrix_float4x4(
            columns: (
                SIMD4<Float>(
                    t * a.x * a.x + c, t * a.x * a.y + s * a.z, t * a.x * a.z - s * a.y, 0),
                SIMD4<Float>(
                    t * a.x * a.y - s * a.z, t * a.y * a.y + c, t * a.y * a.z + s * a.x, 0),
                SIMD4<Float>(
                    t * a.x * a.z + s * a.y, t * a.y * a.z - s * a.x, t * a.z * a.z + c, 0),
                SIMD4<Float>(0, 0, 0, 1)
            ))
        return self * r
    }
}

func matrix_perspective_right_hand(
    fovyRadians fovy: Float,
    aspectRatio: Float,
    nearZ: Float,
    farZ: Float
) -> matrix_float4x4 {
    let ys = 1 / tanf(fovy * 0.5)
    let xs = ys / aspectRatio
    let zs = farZ / (nearZ - farZ)
    return matrix_float4x4(
        columns: (
            SIMD4<Float>(xs, 0, 0, 0),
            SIMD4<Float>(0, ys, 0, 0),
            SIMD4<Float>(0, 0, zs, -1),
            SIMD4<Float>(0, 0, zs * nearZ, 0)
        ))
}

let matrix_identity_float4x4 = matrix_float4x4(
    columns: (
        SIMD4<Float>(1, 0, 0, 0),
        SIMD4<Float>(0, 1, 0, 0),
        SIMD4<Float>(0, 0, 1, 0),
        SIMD4<Float>(0, 0, 0, 1)
    ))
