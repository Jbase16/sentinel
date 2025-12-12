//
//  NeuralGraphView.swift
//  SentinelForgeUI
//
//  The Neural Interface View.
//  Wraps the Metal Renderer for SwiftUI.
//

import SwiftUI
import MetalKit

struct NeuralGraphView: NSViewRepresentable {
    var nodes: [CortexStream.NodeModel]
    
    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }

    func makeNSView(context: Context) -> MTKView {
        let mtkView = MTKView()
        mtkView.delegate = context.coordinator
        mtkView.preferredFramesPerSecond = 60
        mtkView.enableSetNeedsDisplay = true
        
        mtkView.device = MTLCreateSystemDefaultDevice()
        
        mtkView.framebufferOnly = false
        mtkView.clearColor = MTLClearColor(red: 0.05, green: 0.05, blue: 0.1, alpha: 1.0)
        mtkView.drawableSize = mtkView.frame.size
        
        if let device = mtkView.device {
            context.coordinator.renderer = GraphRenderer(device: device)
        }
        
        // Listen for interaction (Simple Bus)
        NotificationCenter.default.addObserver(forName: .cameraMove, object: nil, queue: .main) { note in
            if let delta = note.userInfo?["delta"] as? CGSize {
                context.coordinator.updateInput(drag: delta, zoom: 0)
            }
        }
        
        return mtkView
    }

    func updateNSView(_ nsView: MTKView, context: Context) {
        // Feed live data to the renderer
        context.coordinator.update(nodes: nodes)
    }

    class Coordinator: NSObject, MTKViewDelegate {
        var parent: NeuralGraphView
        var renderer: GraphRenderer?

        init(_ parent: NeuralGraphView) {
            self.parent = parent
            super.init()
        }
        
        func setupRenderer(mtkView: MTKView) {
            if let device = mtkView.device {
                renderer = GraphRenderer(device: device)
                mtkView.delegate = self
            }
        }
        
        func update(nodes: [CortexStream.NodeModel]) {
            renderer?.updateNodes(nodes)
        }
        
        func updateInput(drag: CGSize, zoom: CGFloat) {
            // Convert pixels to rotation radians
            let sens: Float = 0.01
            renderer?.updateCamera(
                rotationX: Float(drag.height) * sens,
                rotationY: Float(drag.width) * sens,
                zoomDelta: Float(zoom)
            )
        }

        func mtkView(_ view: MTKView, drawableSizeWillChange size: CGSize) {
            renderer?.resize(size: size)
        }

        func draw(in view: MTKView) {
            renderer?.draw(in: view)
        }
    }
}
