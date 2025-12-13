//
//  NeuralGraphView.swift
//  SentinelForgeUI
//
//  The Neural Interface View.
//  Wraps the Metal Renderer for SwiftUI.
//

import MetalKit
import SwiftUI

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
        mtkView.colorPixelFormat = .bgra8Unorm  // Explicitly match Pipeline
        mtkView.depthStencilPixelFormat = .invalid  // No depth buffer used
        mtkView.clearColor = MTLClearColor(red: 0.05, green: 0.05, blue: 0.1, alpha: 1.0)
        mtkView.drawableSize = mtkView.frame.size

        if let device = mtkView.device {
            context.coordinator.renderer = GraphRenderer(device: device)
        }

        // Listen for interaction (Simple Bus)
        NotificationCenter.default.addObserver(forName: .cameraMove, object: nil, queue: .main) {
            note in
            if let delta = note.userInfo?["delta"] as? CGSize {
                context.coordinator.updateInput(drag: delta, zoom: 0)
            }
        }

        // Initial data
        context.coordinator.update(nodes: nodes)

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

// MARK: - Interactive Wrapper
struct InteractiveGraphContainer: View {
    @EnvironmentObject var appState: HelixAppState
    @State private var lastDrag = CGSize.zero

    var body: some View {
        NeuralGraphView(nodes: appState.cortexStream.nodes)
            .gesture(
                DragGesture()
                    .onChanged { value in
                        let delta = CGSize(
                            width: value.translation.width - lastDrag.width,
                            height: value.translation.height - lastDrag.height
                        )
                        // Local bridging
                        NotificationCenter.default.post(
                            name: .cameraMove,
                            object: nil,
                            userInfo: ["delta": delta]
                        )
                        lastDrag = value.translation
                    }
                    .onEnded { _ in lastDrag = .zero }
            )
    }
}

extension Notification.Name {
    static let cameraMove = Notification.Name("cameraMove")
}
