import SwiftUI

struct NetworkGraphView: View {
    @StateObject var simulator = ForceSimulator()
    @EnvironmentObject var appState: HelixAppState
    
    var body: some View {
        GeometryReader { geometry in
            ZStack {
                // Background
                Color(NSColor.controlBackgroundColor).opacity(0.5)
                
                // Edges (drawn with Canvas for perf)
                Canvas { context, size in
                    for link in simulator.links {
                        if let src = simulator.nodes.first(where: { $0.id == link.sourceID }),
                           let dst = simulator.nodes.first(where: { $0.id == link.targetID }) {
                            
                            var path = Path()
                            path.move(to: src.position)
                            path.addLine(to: dst.position)
                            
                            context.stroke(path, with: .color(.gray.opacity(0.3)), lineWidth: 1.5)
                        }
                    }
                }
                
                // Nodes
                ForEach(simulator.nodes) { node in
                    Circle()
                        .fill(node.type.color)
                        .frame(width: node.radius * 2, height: node.radius * 2)
                        .position(node.position)
                        .shadow(radius: 2)
                        .overlay(
                            Text(node.label)
                                .font(.caption2)
                                .foregroundColor(.primary)
                                .padding(4)
                                .background(.ultraThinMaterial)
                                .cornerRadius(4)
                                .position(x: node.position.x, y: node.position.y + node.radius + 12)
                                .opacity(0.8)
                        )
                        .onTapGesture {
                            print("Tapped node: \(node.label)")
                        }
                }
            }
            .gesture(
                DragGesture()
                    .onChanged { value in
                        // Simple pan/drag could be added here
                    }
            )
            .onAppear {
                // Sync initial state
                updateGraph()
            }
            .onChange(of: appState.apiResults?.findings?.count) { _ in
                updateGraph()
            }
        }
    }
    
    private func updateGraph() {
        simulator.updateData(
            findings: appState.apiResults?.findings,
            issues: appState.apiResults?.issues,
            target: appState.apiResults?.scan?.target
        )
    }
}
