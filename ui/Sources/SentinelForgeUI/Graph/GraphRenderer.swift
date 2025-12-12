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
    var commandQueue: MTLCommandQueue!
    var pipelineState: MTLRenderPipelineState!
    var vertexBuffer: MTLBuffer?
    var uniformsBuffer: MTLBuffer?
    
    // Scene State
    var time: Float = 0.0
    var viewportSize: CGSize = CGSize(width: 800, height: 600)
    
    // Data Model (Simulated for this file, usually injected)
    struct Node {
        var position: SIMD3<Float>
        var color: SIMD4<Float>
        var size: Float
    }
    
    var nodes: [Node] = []

    init(device: MTLDevice) {
        self.device = device
        super.init()
        self.commandQueue = device.makeCommandQueue()
        buildPipeline()
        generateDummyData() // For visual testing
    }
    
    private func buildPipeline() {
        guard let library = device.makeDefaultLibrary() else { return }
        let vertexFunction = library.makeFunction(name: "vertex_main")
        let fragmentFunction = library.makeFunction(name: "fragment_main")
        
        let pipelineDescriptor = MTLRenderPipelineDescriptor()
        pipelineDescriptor.vertexFunction = vertexFunction
        pipelineDescriptor.fragmentFunction = fragmentFunction
        pipelineDescriptor.colorAttachments[0].pixelFormat = .bgra8Unorm
        
        // Enable transparency
        pipelineDescriptor.colorAttachments[0].isBlendingEnabled = true
        pipelineDescriptor.colorAttachments[0].sourceRGBBlendFactor = .sourceAlpha
        pipelineDescriptor.colorAttachments[0].destinationRGBBlendFactor = .oneMinusSourceAlpha
        
        // Define Vertex Layout
        let vertexDescriptor = MTLVertexDescriptor()
        // Pos
        vertexDescriptor.attributes[0].format = .float3
        vertexDescriptor.attributes[0].offset = 0
        vertexDescriptor.attributes[0].bufferIndex = 0
        // Color
        vertexDescriptor.attributes[1].format = .float4
        vertexDescriptor.attributes[1].offset = MemoryLayout<SIMD3<Float>>.stride
        vertexDescriptor.attributes[1].bufferIndex = 0
        // Size
        vertexDescriptor.attributes[2].format = .float
        vertexDescriptor.attributes[2].offset = MemoryLayout<SIMD3<Float>>.stride + MemoryLayout<SIMD4<Float>>.stride
        vertexDescriptor.attributes[2].bufferIndex = 0
        
        vertexDescriptor.layouts[0].stride = MemoryLayout<Node>.stride
        
        pipelineDescriptor.vertexDescriptor = vertexDescriptor
        
        do {
            pipelineState = try device.makeRenderPipelineState(descriptor: pipelineDescriptor)
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
            
            nodes.append(Node(position: SIMD3<Float>(x, y, z), color: color, size: 20.0))
        }
        
        // Upload to GPU
        let dataSize = nodes.count * MemoryLayout<Node>.stride
        vertexBuffer = device.makeBuffer(bytes: nodes, length: dataSize, options: [])
    }
    
    func resize(size: CGSize) {
        self.viewportSize = size
    }

    func updateNodes(_ newNodes: [CortexStream.NodeModel]) {
        self.nodes = newNodes.map { node in
            // Map node types to colors
            let color: SIMD4<Float>
            switch node.type {
            case "target": color = SIMD4<Float>(1.0, 0.0, 0.2, 1.0) // Red
            case "port": color = SIMD4<Float>(0.0, 1.0, 0.5, 0.8)   // Green
            case "finding": color = SIMD4<Float>(1.0, 0.8, 0.0, 1.0) // Gold
            default: color = SIMD4<Float>(0.0, 0.5, 1.0, 0.5)       // Blue
            }
            
            // Use server coords or random fallout
            let x = node.x ?? Float.random(in: -1...1)
            let y = node.y ?? Float.random(in: -1...1)
            let z = Float.random(in: -0.5...0.5)
            
            return Node(position: SIMD3<Float>(x, y, z), color: color, size: 30.0)
        }
        
        let dataSize = nodes.count * MemoryLayout<Node>.stride
        if dataSize > 0 {
            vertexBuffer = device.makeBuffer(bytes: nodes, length: dataSize, options: [])
        }
    }

    // Interaction State
    var rotationX: Float = 0
    var rotationY: Float = 0
    var zoom: Float = -200.0 // Move back to see the scene

    func updateCamera(rotationX: Float, rotationY: Float, zoomDelta: Float) {
        self.rotationX += rotationX
        self.rotationY += rotationY
        self.zoom += zoomDelta * 5.0
        self.zoom = min(max(self.zoom, -500), -10)
    }

    func draw(in view: MTKView) {
        guard let drawable = view.currentDrawable,
              let descriptor = view.currentRenderPassDescriptor,
              let pipelineState = pipelineState else {
            return
        }
        
        // Update Time
        time += 0.015
        
        // --- 3D Transforms ---
        let aspect = Float(viewportSize.width / viewportSize.height)
        let projectionMatrix = matrix_perspective_right_hand(fovyRadians: Float.pi / 4.0, aspectRatio: aspect, nearZ: 1.0, farZ: 1000.0)
        
        // Camera Orbit
        let viewMatrix = matrix_identity_float4x4
            .translated(x: 0, y: 0, z: zoom)
            .rotated(angle: rotationX, axis: SIMD3<Float>(1, 0, 0))
            .rotated(angle: rotationY, axis: SIMD3<Float>(0, 1, 0))
            
        // Rotate the cloud itself slightly for dynamism
        let modelMatrix = matrix_identity_float4x4.rotated(angle: time * 0.1, axis: SIMD3<Float>(0, 1, 0))
        
        let viewProjection = projectionMatrix * viewMatrix
        
        struct Uniforms {
            var viewProjection: matrix_float4x4
            var model: matrix_float4x4
            var time: Float
        }
        
        var uniforms = Uniforms(viewProjection: viewProjection, model: modelMatrix, time: time)
        
        let commandBuffer = commandQueue.makeCommandBuffer()!
        let encoder = commandBuffer.makeRenderCommandEncoder(descriptor: descriptor)!
        
        encoder.setRenderPipelineState(pipelineState)
        
        // Enable Depth Testing if we had a depth buffer (omitted for pure additive particle look)
        // For cyber particles, additive blending (set in pipeline) handles "depth" sorting visually.
        
        encoder.setVertexBytes(&uniforms, length: MemoryLayout<Uniforms>.size, index: 1)
        
        if let vBuffer = vertexBuffer, !nodes.isEmpty {
            encoder.setVertexBuffer(vBuffer, offset: 0, index: 0)
            encoder.drawPrimitives(type: .point, vertexStart: 0, vertexCount: nodes.count)
        }
        
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
        let rows = [
            SIMD3<Float>(1, 0, 0),
            SIMD3<Float>(0, 1, 0),
            SIMD3<Float>(0, 0, 1)
        ]
        // Simplified rotation around cardinality (production engines use quaternions)
        // This is a naive implementation sufficient for demo axis rotation.
        let c = cos(angle)
        let s = sin(angle)
        
        if axis.x > 0 { // Rotate X
             return self * matrix_float4x4(columns: (
                 SIMD4<Float>(1, 0, 0, 0),
                 SIMD4<Float>(0, c, s, 0),
                 SIMD4<Float>(0, -s, c, 0),
                 SIMD4<Float>(0, 0, 0, 1)
             ))
        } else { // Rotate Y (Assuming axis y > 0)
             return self * matrix_float4x4(columns: (
                 SIMD4<Float>(c, 0, -s, 0),
                 SIMD4<Float>(0, 1, 0, 0),
                 SIMD4<Float>(s, 0, c, 0),
                 SIMD4<Float>(0, 0, 0, 1)
             ))
        }
    }
}

func matrix_perspective_right_hand(fovyRadians fovy: Float, aspectRatio: Float, nearZ: Float, farZ: Float) -> matrix_float4x4 {
    let ys = 1 / tanf(fovy * 0.5)
    let xs = ys / aspectRatio
    let zs = farZ / (nearZ - farZ)
    return matrix_float4x4.init(columns:(vector_float4(xs,  0, 0,   0),
                                         vector_float4( 0, ys, 0,   0),
                                         vector_float4( 0,  0, zs, -1),
                                         vector_float4( 0,  0, zs * nearZ, 0)))
}

let matrix_identity_float4x4 = matrix_float4x4(columns:(vector_float4(1,0,0,0),
                                                        vector_float4(0,1,0,0),
                                                        vector_float4(0,0,1,0),
                                                        vector_float4(0,0,0,1)))
