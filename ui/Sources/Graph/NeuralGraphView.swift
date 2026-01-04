//
// PURPOSE:
// This Swift component is part of the SentinelForge macOS UI.
// [Specific purpose based on component name: NeuralGraphView]
//
// KEY RESPONSIBILITIES:
// - [Automatically generated - review and enhance based on actual functionality]
//
// INTEGRATION:
// - Used by: [To be documented]
// - Depends on: [To be documented]
//

//
//  NeuralGraphView.swift
//  SentinelForgeUI
//
//  The Neural Interface View.
//  Wraps the Metal Renderer for SwiftUI.
//

import Combine
import MetalKit
import SwiftUI

/// Struct NeuralGraphView.
struct NeuralGraphView: NSViewRepresentable {
    let eventClient: EventStreamClient
    let nodes: [CortexStream.NodeModel]  // Data Binding

    func makeCoordinator() -> Coordinator {
        Coordinator(eventClient: eventClient)
    }

    @MainActor
    func makeNSView(context: Context) -> MTKView {
        let mtkView = MTKView()
        mtkView.delegate = context.coordinator
        mtkView.preferredFramesPerSecond = 60
        mtkView.enableSetNeedsDisplay = true
        mtkView.device = MTLCreateSystemDefaultDevice()
        mtkView.framebufferOnly = false
        mtkView.colorPixelFormat = .bgra8Unorm
        mtkView.depthStencilPixelFormat = .invalid
        mtkView.clearColor = MTLClearColor(red: 0.05, green: 0.05, blue: 0.1, alpha: 1.0)
        mtkView.drawableSize = mtkView.frame.size

        if let device = mtkView.device {
            context.coordinator.renderer = GraphRenderer(device: device)
        }

        NotificationCenter.default.addObserver(forName: .cameraMove, object: nil, queue: .main) {
            note in
            if let delta = note.userInfo?["delta"] as? CGSize {
                context.coordinator.updateInput(drag: delta, zoom: 0)
            }
        }

        context.coordinator.bindEventStream(view: mtkView)
        // Initial Update
        context.coordinator.updateNodes(nodes)

        return mtkView
    }

    @MainActor
    func updateNSView(_ nsView: MTKView, context: Context) {
        // Continuous Update
        context.coordinator.updateNodes(nodes)

        // Don't re-bind event stream if not needed, but harmless to leave logic if stable
    }

    class Coordinator: NSObject, MTKViewDelegate {
        var renderer: GraphRenderer?
        private let eventClient: EventStreamClient
        private var graphCancellable: AnyCancellable?
        private weak var mtkView: MTKView?

        init(eventClient: EventStreamClient) {
            self.eventClient = eventClient
            super.init()
        }

        func updateNodes(_ nodes: [CortexStream.NodeModel]) {
            renderer?.updateNodes(nodes)
            mtkView?.setNeedsDisplay(mtkView?.bounds ?? .zero)
        }

        @MainActor
        func bindEventStream(view: MTKView) {
            self.mtkView = view
            guard graphCancellable == nil else { return }

            graphCancellable = eventClient.eventPublisher
                .receive(on: RunLoop.main)
                .sink { [weak self] event in
                    guard let self, let renderer = self.renderer else { return }
                    renderer.handleGraphEvent(
                        GraphRenderer.Event(typeString: event.type, payload: event.payload)
                    )
                    self.mtkView?.setNeedsDisplay(self.mtkView?.bounds ?? .zero)
                }
        }

        // ... rest of delegate
        func updateInput(drag: CGSize, zoom: CGFloat) {
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
        NeuralGraphView(
            eventClient: appState.eventClient,
            nodes: appState.cortexStream.nodes
        )
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
