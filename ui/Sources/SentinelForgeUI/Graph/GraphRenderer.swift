//
//  GraphRenderer.swift
//  SentinelForgeUI
//
//  The Engine Room.
//  Manages the Metal Pipeline, Buffers, and Physics Simulation.
//

import Metal
import MetalKit
import simd

class GraphRenderer: NSObject {
    var device: MTLDevice
    var commandQueue: MTLCommandQueue?  // Changed from ! to ? for safety
    var pipelineState: MTLRenderPipelineState?  // Changed from ! to ?
    var vertexBuffer: MTLBuffer?
    var uniformsBuffer: MTLBuffer?

    // Scene State
    var time: Float = 0.0
    var viewportSize: CGSize = CGSize(width: 800, height: 600)

    // Data Model: Directly maps to Metal Layout (32 bytes aligned)
    struct Node {
        var position: SIMD4<Float>  // xyz = pos, w = size
        var color: SIMD4<Float>
    }

    var nodes: [Node] = []

    init(device: MTLDevice) {
        print("GraphRenderer: init() called")
        self.device = device
        super.init()
        self.commandQueue = device.makeCommandQueue()
        print("GraphRenderer: commandQueue created: \(self.commandQueue != nil)")
        buildPipeline()
        generateDummyData()
        print("GraphRenderer: init() complete")
    }

    private func buildPipeline() {
        print("GraphRenderer: buildPipeline()")
        guard let library = device.makeDefaultLibrary() else {
            print("GraphRenderer: Default library not found")
            return
        }
        let vertexFunction = library.makeFunction(name: "vertex_main")
        let fragmentFunction = library.makeFunction(name: "fragment_main")
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

        vertexDescriptor.layouts[0].stride = 32  // 16 + 16

        pipelineDescriptor.vertexDescriptor = vertexDescriptor

        do {
            pipelineState = try device.makeRenderPipelineState(descriptor: pipelineDescriptor)
            print("GraphRenderer: Pipeline State created successfully")
        } catch {
            print("Failed to create pipeline: \(error)")
        }
    }

    private func generateDummyData() {
        // Create a "Cyberpunk Cloud" of nodes
        for _ in 0..<100 {
            let x = Float.random(in: -1...1)
            let y = Float.random(in: -1...1)
            let z = Float.random(in: -0.5...0.5)

            // Neon Cyan / Magenta theme
            let isRed = Bool.random()
            let color = isRed ? SIMD4<Float>(1.0, 0.0, 0.5, 0.8) : SIMD4<Float>(0.0, 0.8, 1.0, 0.8)

            // Pack size into w (20.0)
            nodes.append(Node(position: SIMD4<Float>(x, y, z, 20.0), color: color))
        }

        // Upload to GPU
        let dataSize = nodes.count * MemoryLayout<Node>.stride
        vertexBuffer = device.makeBuffer(bytes: nodes, length: dataSize, options: [])
    }

    func resize(size: CGSize) {
        self.viewportSize = size
    }

    // Thread Safety
    private let lock = NSLock()

    func updateNodes(_ newNodes: [CortexStream.NodeModel]) {
        lock.lock()
        defer { lock.unlock() }

        self.nodes = newNodes.map { node in
            // Use server coords or fallback to random
            let x = node.x ?? Float.random(in: -1...1)
            let y = node.y ?? Float.random(in: -1...1)
            let z = node.z ?? Float.random(in: -0.5...0.5)

            // Use pre-computed color or fallback
            // Ensure alpha is sufficient for visibility
            let color = node.color ?? SIMD4<Float>(0.0, 0.5, 1.0, 0.8)

            // Pack size (30.0)
            return Node(position: SIMD4<Float>(x, y, z, 30.0), color: color)
        }

        let dataSize = nodes.count * MemoryLayout<Node>.stride
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

    func draw(in view: MTKView) {
        lock.lock()
        defer { lock.unlock() }

        // Watchdog: Log every 60 frames (approx 1 sec)
        frameCount += 1
        if frameCount % 60 == 0 {
            print("GraphRenderer: Watchdog - Drawing frame \(frameCount). Nodes: \(nodes.count)")
        }

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

        guard let commandBuffer = commandQueue.makeCommandBuffer(),
            let encoder = commandBuffer.makeRenderCommandEncoder(descriptor: descriptor)
        else {
            return
        }

        encoder.setRenderPipelineState(pipelineState)

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

        struct Uniforms {
            var viewProjection: matrix_float4x4
            var model: matrix_float4x4
            var time: Float
        }

        var uniforms = Uniforms(viewProjection: viewProjection, model: modelMatrix, time: time)

        // Pass Uniforms
        encoder.setVertexBytes(&uniforms, length: MemoryLayout<Uniforms>.size, index: 1)

        // Safe Drawing
        guard !nodes.isEmpty, let vBuffer = vertexBuffer else {
            if frameCount % 60 == 0 {
                print("GraphRenderer: Nodes empty. Skipping draw primitives.")
            }
            encoder.endEncoding()
            commandBuffer.present(drawable)
            commandBuffer.commit()
            return
        }

        encoder.setVertexBuffer(vBuffer, offset: 0, index: 0)
        encoder.drawPrimitives(
            type: MTLPrimitiveType.point, vertexStart: 0, vertexCount: nodes.count)

        encoder.endEncoding()
        commandBuffer.present(drawable)
        commandBuffer.commit()
    }
}

// --- Matrix Math Factory ---

extension matrix_float4x4 {
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

    func rotated(angle: Float, axis: SIMD3<Float>) -> matrix_float4x4 {
        // Simplified rotation around cardinality (production engines use quaternions)
        // This is a naive implementation sufficient for demo axis rotation.
        let c = cos(angle)
        let s = sin(angle)

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
