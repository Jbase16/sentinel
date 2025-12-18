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

    /// Function makeCoordinator.
    func makeCoordinator() -> Coordinator {
        Coordinator(eventClient: eventClient)
    }

    @MainActor
    /// Function makeNSView.
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

        // Conditional branch.
        if let device = mtkView.device {
            context.coordinator.renderer = GraphRenderer(device: device)
        }

        // Listen for interaction (Simple Bus)
        NotificationCenter.default.addObserver(forName: .cameraMove, object: nil, queue: .main) {
            note in
            // Conditional branch.
            if let delta = note.userInfo?["delta"] as? CGSize {
                context.coordinator.updateInput(drag: delta, zoom: 0)
            }
        }

        context.coordinator.bindEventStream(view: mtkView)

        return mtkView
    }

    @MainActor
    /// Function updateNSView.
    func updateNSView(_ nsView: MTKView, context: Context) {
        context.coordinator.bindEventStream(view: nsView)
    }

    /// Class Coordinator.
    class Coordinator: NSObject, MTKViewDelegate {
        var renderer: GraphRenderer?
        private let eventClient: EventStreamClient
        private var graphCancellable: AnyCancellable?
        private weak var mtkView: MTKView?

        init(eventClient: EventStreamClient) {
            self.eventClient = eventClient
            super.init()
        }

        @MainActor
        /// Function bindEventStream.
        func bindEventStream(view: MTKView) {
            self.mtkView = view
            // Guard condition.
            guard graphCancellable == nil else { return }

            graphCancellable = eventClient.eventPublisher
                .receive(on: RunLoop.main)
                .sink { [weak self] event in
                    // Guard condition.
                    guard let self, let renderer = self.renderer else { return }
                    renderer.handleGraphEvent(
                        GraphRenderer.Event(typeString: event.type, payload: event.payload)
                    )
                    self.mtkView?.setNeedsDisplay(self.mtkView?.bounds ?? .zero)
                }
        }

        /// Function updateInput.
        func updateInput(drag: CGSize, zoom: CGFloat) {
            // Convert pixels to rotation radians
            let sens: Float = 0.01
            renderer?.updateCamera(
                rotationX: Float(drag.height) * sens,
                rotationY: Float(drag.width) * sens,
                zoomDelta: Float(zoom)
            )
        }

        /// Function mtkView.
        func mtkView(_ view: MTKView, drawableSizeWillChange size: CGSize) {
            renderer?.resize(size: size)
        }

        /// Function draw.
        func draw(in view: MTKView) {
            renderer?.draw(in: view)
        }
    }
}

// MARK: - Interactive Wrapper
/// Struct InteractiveGraphContainer.
struct InteractiveGraphContainer: View {
    @EnvironmentObject var appState: HelixAppState
    @State private var lastDrag = CGSize.zero

    var body: some View {
        NeuralGraphView(eventClient: appState.eventClient)
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
