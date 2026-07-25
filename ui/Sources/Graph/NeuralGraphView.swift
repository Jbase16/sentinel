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
import Foundation
import MetalKit
import SwiftUI

/// Struct NeuralGraphView.
struct GraphLabel: Identifiable, Equatable {
    let id: String
    let pos: CGPoint
    let text: String
    let intensity: Float
}

struct NeuralGraphView: NSViewRepresentable {
    let eventClient: EventStreamClient
    let nodes: [CortexStream.NodeModel]
    let edges: [CortexStream.EdgeModel]
    let analysis: TopologyResponse?  // Phase 11
    @Binding var selectedNodeId: String?
    @Binding var selectedNodePoint: CGPoint?  // For Overlay
    @Binding var labels: [GraphLabel]  // Layer 1: Persistent Labels

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
        context.coordinator.updateEdges(edges)

        return mtkView
    }

    @MainActor
    func updateNSView(_ nsView: MTKView, context: Context) {
        context.coordinator.parent = self
        context.coordinator.updateNodes(nodes)
        context.coordinator.updateEdges(edges)

        // Phase 11: Critical Paths
        if let paths = analysis?.critical_paths {
            context.coordinator.updateCriticalPaths(paths.map { $0.path })
        } else {
            context.coordinator.updateCriticalPaths([])
        }

        // Update selection in renderer if changed externally
        context.coordinator.updateSelection(selectedNodeId)
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

        func updateCriticalPaths(_ paths: [[String]]) {
            renderer?.setCriticalPaths(paths)
            mtkView?.setNeedsDisplay(mtkView?.bounds ?? .zero)
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
            // Defer to avoid "Modifying state during view update"
            DispatchQueue.main.async { [weak self] in
                guard let self = self else { return }
                if let id = self.parent.selectedNodeId,
                    let point = self.renderer?.projectNode(id: id)
                {
                    self.parent.selectedNodePoint = point
                }
            }
        }

        func updateEdges(_ edges: [CortexStream.EdgeModel]) {
            let rendererEdges = edges.map {
                GraphRenderer.EdgeData(
                    source: $0.source, target: $0.target, type: $0.type ?? "unknown")
            }
            renderer?.updateEdges(rendererEdges)
        }

        func updateSelection(_ id: String?) {
            renderer?.setSelected(id)

            // Force immediate overlay update to avoid lag
            // Defer to avoid "Modifying state during view update"
            DispatchQueue.main.async { [weak self] in
                guard let self = self else { return }
                if let id = id, let point = self.renderer?.projectNode(id: id) {
                    self.parent.selectedNodePoint = point
                } else {
                    self.parent.selectedNodePoint = nil
                }
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

            // Sync Labels
            // Throttle: Update labels every 2 frames to reduce SwiftUI churn, or just direct update.
            // Since we are on the main thread (MTKViewDelegate), we can update bindings directly.
            // Check if we actually have visible labels to avoid empty updates.

            if let visible = renderer?.getVisibleLabels() {
                let newLabels = visible.map {
                    GraphLabel(id: $0.id, pos: $0.pos, text: $0.label, intensity: $0.pressure)
                }

                // Direct update (No async dispatch) = No frame lag
                self.parent.labels = newLabels

                // Sync Selection Overlay position
                if let id = self.parent.selectedNodeId,
                    let point = self.renderer?.projectNode(id: id)
                {
                    self.parent.selectedNodePoint = point
                }
            }
        }
    }
}

// MARK: - Interactive Wrapper
// MARK: - Interactive Wrapper
struct InteractiveGraphContainer: View {
    @EnvironmentObject var appState: HelixAppState
    @State private var lastDrag = CGSize.zero
    @State private var selectedNodeId: String? = nil
    @State private var selectedOverlayPos: CGPoint? = nil
    @State private var labels: [GraphLabel] = []  // Layer 1 Labels

    var body: some View {
        ZStack {
            NeuralGraphView(
                eventClient: appState.eventClient,
                nodes: appState.cortexStream.nodes,
                edges: appState.cortexStream.edges,
                analysis: appState.graphAnalysis,
                selectedNodeId: $selectedNodeId,
                selectedNodePoint: $selectedOverlayPos,
                labels: $labels
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
            .onChange(of: selectedNodeId) {
                if let id = selectedNodeId {
                    // Trigger Analysis (Phase 11)
                    appState.fetchInsights(for: id)
                }
            }
            .onChange(of: appState.isScanRunning) {
                if !appState.isScanRunning {
                    // Refresh Analysis when scan completes
                    appState.fetchAnalysis()
                }
            }

            // LAYER 1: PERSISTENT LABELS (Contextual Density)
            ForEach(labels) { label in
                Text(label.text)
                    .font(.system(size: 9, weight: .semibold, design: .monospaced))
                    .foregroundColor(Color.white.opacity(Double(0.4 + label.intensity * 0.6)))
                    .position(x: label.pos.x, y: label.pos.y + 16)  // Offset below node
                    .allowsHitTesting(false)
            }

            // OVERLAY LAYER
            if let id = selectedNodeId, let pos = selectedOverlayPos {
                let selectedNode = appState.cortexStream.nodes.first { $0.id == id }
                let insights = appState.insightsByNode[id] ?? []

                VStack(alignment: .leading, spacing: 4) {
                    Text(id)
                        .font(.system(size: 12, weight: .bold, design: .monospaced))
                        .foregroundColor(.cyan)
                    Text(selectedNode?.description ?? "Analysis Pending...")
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.white.opacity(0.8))

                    if !insights.isEmpty {
                        Divider().background(Color.white.opacity(0.3))
                        ForEach(insights.prefix(3)) { insight in
                            HStack(alignment: .top, spacing: 4) {
                                Image(systemName: "sparkles")
                                    .font(.system(size: 8))
                                    .foregroundColor(.purple)
                                Text(insight.claim)
                                    .font(.system(size: 9))
                                    .foregroundColor(.white)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }
                }
                .padding(8)
                .background(Color.black.opacity(0.85))
                .cornerRadius(6)
                .overlay(
                    RoundedRectangle(cornerRadius: 6)
                        .stroke(Color.cyan.opacity(0.5), lineWidth: 1)
                )
                .frame(maxWidth: 220)  // Limit width for readability
                .position(x: pos.x, y: pos.y - 60)  // Offset above node
                .allowsHitTesting(false)  // Pass touches through
            }

            VStack {
                HStack(alignment: .top) {
                    Spacer()
                    FixImpactPanel(
                        graph: appState.latestPressureGraph,
                        selectedNodeId: $selectedNodeId
                    )
                    .padding(.top, 72)
                    .padding(.trailing, 16)
                }
                Spacer()
            }
        }
    }
}

private struct FixImpactPanel: View {
    let graph: PressureGraphDTO?
    @Binding var selectedNodeId: String?

    private var rankedPoints: [PressurePointDTO] {
        guard let points = graph?.pressurePoints else { return [] }
        return points.sorted { lhs, rhs in
            let lhsBlocked = lhs.attackPathsBlocked ?? 0
            let rhsBlocked = rhs.attackPathsBlocked ?? 0
            if lhsBlocked != rhsBlocked { return lhsBlocked > rhsBlocked }
            let lhsCentrality = lhs.centralityScore ?? 0
            let rhsCentrality = rhs.centralityScore ?? 0
            if lhsCentrality != rhsCentrality { return lhsCentrality > rhsCentrality }
            return (lhs.enablementScore ?? 0) > (rhs.enablementScore ?? 0)
        }
    }

    private var selectedNodeData: PressureNodeDataDTO? {
        guard let nodeId = selectedNodeId else { return nil }
        return graph?.nodes.first(where: { $0.id == nodeId })?.data
    }

    private var selectedPressurePoint: PressurePointDTO? {
        guard let nodeId = selectedNodeId else { return nil }
        return rankedPoints.first(where: { $0.findingId == nodeId })
    }

    private var selectedUpstreamCount: Int {
        guard let nodeId = selectedNodeId else { return 0 }
        return graph?.edges.filter { $0.target == nodeId }.count ?? 0
    }

    private var selectedDownstreamCount: Int {
        guard let nodeId = selectedNodeId else { return 0 }
        return graph?.edges.filter { $0.source == nodeId }.count ?? 0
    }

    private var selectedChainCount: Int {
        guard let nodeId = selectedNodeId else { return 0 }
        if let explicitCount = selectedNodeData?.attackChainMembership {
            return explicitCount
        }
        let chains = graph?.attackChains ?? []
        return chains.filter { $0.nodeIds.contains(nodeId) }.count
    }

    private func severityColor(_ severity: String?) -> Color {
        let value = (severity ?? "").uppercased()
        switch value {
        case "CRITICAL":
            return Color(red: 1.0, green: 0.2, blue: 0.2)
        case "HIGH":
            return Color(red: 1.0, green: 0.55, blue: 0.2)
        case "MEDIUM":
            return Color(red: 1.0, green: 0.85, blue: 0.25)
        case "LOW":
            return Color(red: 0.3, green: 0.75, blue: 1.0)
        default:
            return Color.gray
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            headerView
            selectedNodeDetailsView
            Divider().background(Color.white.opacity(0.25))
            pressurePointsListView
        }
        .padding(12)
        .frame(width: 360, alignment: .topLeading)
        .background(Color.black.opacity(0.72))
        .cornerRadius(10)
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .stroke(Color.white.opacity(0.15), lineWidth: 1)
        )
        .shadow(color: Color.black.opacity(0.4), radius: 6, x: 0, y: 4)
    }

    private var headerView: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("FIX IMPACT")
                .font(.system(size: 12, weight: .bold, design: .monospaced))
                .foregroundColor(.white)

            HStack(spacing: 10) {
                Text("Pressure: \(rankedPoints.count)")
                Text("Chains: \(graph?.attackChains?.count ?? 0)")
                Text("Entries: \(graph?.entryNodes?.count ?? 0)")
            }
            .font(.system(size: 10, design: .monospaced))
            .foregroundColor(.white.opacity(0.75))
        }
    }

    @ViewBuilder
    private var selectedNodeDetailsView: some View {
        if let selected = selectedNodeId {
            VStack(alignment: .leading, spacing: 4) {
                Text("Selected: \(selected)")
                    .font(.system(size: 10, weight: .semibold, design: .monospaced))
                    .foregroundColor(.cyan)

                let blocked =
                    selectedNodeData?.fixImpactEstimate
                    ?? selectedPressurePoint?.attackPathsBlocked
                    ?? 0
                let confidence = selectedNodeData?.confirmationLevel?.uppercased() ?? "UNKNOWN"
                Text(
                    "Blocks ~\(blocked) paths | Upstream \(selectedUpstreamCount) | Downstream \(selectedDownstreamCount)"
                )
                .font(.system(size: 9, design: .monospaced))
                .foregroundColor(.white.opacity(0.85))

                Text("Chains \(selectedChainCount) | Confirmation \(confidence)")
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(.white.opacity(0.75))

                if let caps = selectedNodeData?.capabilityTypes, !caps.isEmpty {
                    Text("Capabilities: \(caps.joined(separator: ", "))")
                        .font(.system(size: 9, design: .monospaced))
                        .foregroundColor(.white.opacity(0.75))
                        .lineLimit(2)
                }
            }
            .padding(8)
            .background(Color.black.opacity(0.35))
            .cornerRadius(6)
        }
    }

    @ViewBuilder
    private var pressurePointsListView: some View {
        if rankedPoints.isEmpty {
            Text("No pressure points available yet.")
                .font(.system(size: 10, design: .monospaced))
                .foregroundColor(.white.opacity(0.7))
        } else {
            ScrollView {
                VStack(spacing: 6) {
                    ForEach(Array(rankedPoints.prefix(10).enumerated()), id: \.element.id) {
                        index, point in
                        Button {
                            selectedNodeId = point.findingId
                        } label: {
                            HStack(alignment: .top, spacing: 8) {
                                Text("#\(index + 1)")
                                    .font(.system(size: 10, weight: .bold, design: .monospaced))
                                    .foregroundColor(.white.opacity(0.75))
                                    .frame(width: 24, alignment: .leading)

                                VStack(alignment: .leading, spacing: 2) {
                                    Text(point.findingTitle ?? point.findingId)
                                        .font(.system(size: 10, weight: .semibold))
                                        .foregroundColor(.white)
                                        .lineLimit(2)
                                        .multilineTextAlignment(.leading)

                                    Text(
                                        "Blocks \(point.attackPathsBlocked ?? 0) | Out \(point.outDegree ?? 0) | C \(String(format: "%.2f", point.centralityScore ?? 0)) | E \(String(format: "%.2f", point.enablementScore ?? 0))"
                                    )
                                    .font(.system(size: 9, design: .monospaced))
                                    .foregroundColor(.white.opacity(0.75))
                                }

                                Spacer(minLength: 0)

                                Circle()
                                    .fill(severityColor(point.severity))
                                    .frame(width: 7, height: 7)
                                    .padding(.top, 4)
                            }
                            .padding(6)
                            .background(
                                RoundedRectangle(cornerRadius: 6)
                                    .fill(
                                        selectedNodeId == point.findingId
                                            ? Color.cyan.opacity(0.22)
                                            : Color.white.opacity(0.04)
                                    )
                            )
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
            .frame(maxHeight: 280)
        }
    }
}

extension Notification.Name {
    static let cameraMove = Notification.Name("cameraMove")
}
