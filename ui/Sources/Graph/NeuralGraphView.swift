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
    let nodes: [CortexStream.NodeModel]
    @Binding var selectedNodeId: String?
    @Binding var selectedNodePoint: CGPoint?  // For Overlay

    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }

    @MainActor
    func makeNSView(context: Context) -> MTKView {
        let mtkView = MTKView()
        mtkView.delegate = context.coordinator
        mtkView.device = MTLCreateSystemDefaultDevice()

        if let device = mtkView.device {
            let renderer = GraphRenderer(device: device)
            renderer.configure(view: mtkView)
            context.coordinator.renderer = renderer
        }

        NotificationCenter.default.addObserver(forName: .cameraMove, object: nil, queue: .main) {
            note in
            if let delta = note.userInfo?["delta"] as? CGSize {
                context.coordinator.updateInput(drag: delta, zoom: 0)
            }
        }

        // Click Gesture
        let click = NSClickGestureRecognizer(
            target: context.coordinator, action: #selector(Coordinator.handleClick(_:)))
        mtkView.addGestureRecognizer(click)

        context.coordinator.bindEventStream(view: mtkView)
        context.coordinator.updateNodes(nodes)

        return mtkView
    }

    @MainActor
    func updateNSView(_ nsView: MTKView, context: Context) {
        context.coordinator.parent = self
        context.coordinator.updateNodes(nodes)

        // Update selection in renderer if changed externally (optional)
        // context.coordinator.renderer?.setSelected(selectedNodeId)
    }

    class Coordinator: NSObject, MTKViewDelegate {
        var parent: NeuralGraphView
        var renderer: GraphRenderer?
        private var graphCancellable: AnyCancellable?
        private weak var mtkView: MTKView?

        init(_ parent: NeuralGraphView) {
            self.parent = parent
            super.init()
        }

        @objc func handleClick(_ gesture: NSClickGestureRecognizer) {
            guard let view = gesture.view else { return }
            let location = gesture.location(in: view)

            // Convert NSView (Bottom-Left) to Metal/CG (Top-Left) if needed?
            // MetalNDC Y is flipped. CG coords usually Top-Left.
            // NSView coords are Bottom-Left.
            // But we used `location.y / height` in hitTest assuming top-left?
            // Wait, hitTest: `let y_ndc = Float(1.0 - (location.y / viewportSize.height) * 2.0)`.
            // If location.y is 0 (top in CG), y_ndc = 1.0. Correct for Metal.
            // If NSView is Bottom-Left, y=0 is bottom. Then y_ndc = 1.0 (top). That's inverted.
            // In macOS, NSView uses Bottom-Left origin.
            // We should check `view.isFlipped`. MTKView is usually not flipped (0,0 at bottom-left).
            // So if clicked at top (y=height), y_ndc should be 1.0? No, Metal NDC y=1 is UP.
            // If y=0 (bottom), y_ndc = 1.0 - 0 = 1.0. Correct?
            // In Metal NDC, y=1 is top.
            // If we click bottom (y=0 in NSView), we want y_ndc = -1.
            // Formula used: `1.0 - (y/h)*2`.
            // If y=0 -> 1.0. (Top).
            // If y=h -> -1.0. (Bottom).
            // This assumes y increases downwards (Top-Left 0,0).
            // NSView is Bottom-Left 0,0.
            // So we need to flip the input Y if view is not flipped.
            // Or adjust the formula.
            // Let's pass the raw location and handle logic in selectNode or here.

            // Standardizing to Top-Left for Renderer logic:
            var adjustedLocation = location
            if !view.isFlipped {
                adjustedLocation.y = view.bounds.height - location.y
            }

            if let id = renderer?.selectNode(at: adjustedLocation) {
                parent.selectedNodeId = id
                // Project immediately for overlay
                parent.selectedNodePoint = renderer?.projectNode(id: id)
            } else {
                parent.selectedNodeId = nil
                parent.selectedNodePoint = nil
            }
        }

        func updateNodes(_ nodes: [CortexStream.NodeModel]) {
            renderer?.updateNodes(nodes)
            mtkView?.setNeedsDisplay(mtkView?.bounds ?? .zero)

            // Update overlay position if selected
            if let id = parent.selectedNodeId, let point = renderer?.projectNode(id: id) {
                parent.selectedNodePoint = point
            }
        }

        @MainActor
        func bindEventStream(view: MTKView) {
            self.mtkView = view
            guard graphCancellable == nil else { return }

            graphCancellable = parent.eventClient.eventPublisher
                .receive(on: RunLoop.main)
                .sink { [weak self] event in
                    guard let self, let renderer = self.renderer else { return }
                    renderer.handleGraphEvent(
                        GraphRenderer.Event(typeString: event.type, payload: event.payload)
                    )
                    self.mtkView?.setNeedsDisplay(self.mtkView?.bounds ?? .zero)

                    // Update overlay on event
                    if let id = self.parent.selectedNodeId, let point = renderer.projectNode(id: id)
                    {
                        self.parent.selectedNodePoint = point
                    }
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
            // Update overlay on camera move
            if let id = parent.selectedNodeId, let point = renderer?.projectNode(id: id) {
                parent.selectedNodePoint = point
            }
        }

        func mtkView(_ view: MTKView, drawableSizeWillChange size: CGSize) {
            renderer?.resize(size: size)
        }

        func draw(in view: MTKView) {
            renderer?.draw(in: view)
            // Ideally we check overlay position here too but `draw` is high freq.
            // Can use a separate timer or just rely on events/input.
        }
    }
}

// MARK: - Interactive Wrapper
struct InteractiveGraphContainer: View {
    @EnvironmentObject var appState: HelixAppState
    @State private var lastDrag = CGSize.zero
    @State private var selectedNodeId: String? = nil
    @State private var selectedOverlayPos: CGPoint? = nil

    var body: some View {
        ZStack {
            NeuralGraphView(
                eventClient: appState.eventClient,
                nodes: appState.cortexStream.nodes,
                selectedNodeId: $selectedNodeId,
                selectedNodePoint: $selectedOverlayPos
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

            // OVERLAY LAYER
            if let id = selectedNodeId, let pos = selectedOverlayPos {
                VStack(alignment: .leading, spacing: 4) {
                    Text(id)
                        .font(.system(size: 12, weight: .bold, design: .monospaced))
                        .foregroundColor(.cyan)
                    Text("Analysis Pending...")
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.white.opacity(0.8))
                }
                .padding(8)
                .background(Color.black.opacity(0.8))
                .cornerRadius(6)
                .overlay(
                    RoundedRectangle(cornerRadius: 6)
                        .stroke(Color.cyan.opacity(0.5), lineWidth: 1)
                )
                .position(x: pos.x, y: pos.y - 40)  // Offset above node
                .allowsHitTesting(false)  // Pass touches through
            }
        }
    }
}

extension Notification.Name {
    static let cameraMove = Notification.Name("cameraMove")
}
