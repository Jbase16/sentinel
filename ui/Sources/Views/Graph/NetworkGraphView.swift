import SwiftUI

struct NetworkGraphView: View {
    @EnvironmentObject var appState: HelixAppState

    var body: some View {
        ZStack {
            // The Metal View (Interactive)
            InteractiveGraphContainer()
                .ignoresSafeArea()

            // Overlay HUD
            VStack {
                HStack {
                    Text("NEURAL INTERFACE :: LIVE")
                        .font(.custom("Courier New", size: 14))
                        .foregroundColor(.green)
                        .padding(8)
                        .background(.ultraThinMaterial)
                        .cornerRadius(4)

                    if appState.cortexStream.isConnected {
                        Text("GHOST PROTOCOL :: ACTIVE")
                            .font(.custom("Courier New", size: 14))
                            .foregroundColor(.orange)
                            .padding(8)
                            .background(.ultraThinMaterial)
                            .cornerRadius(4)
                    }

                    Spacer()

                    Text("NODES: \(appState.cortexStream.nodes.count)")
                        .font(.custom("Courier New", size: 12))
                        .foregroundColor(.white)
                }
                .padding()

                Spacer()

                // Legend
                HStack(spacing: 12) {
                    Circle().fill(Color(red: 1, green: 0.2, blue: 0.2)).frame(width: 8, height: 8)
                    Text("Target").font(.caption).foregroundColor(.white)

                    Circle().fill(Color.green).frame(width: 8, height: 8)
                    Text("Port").font(.caption).foregroundColor(.white)

                    Circle().fill(Color.orange).frame(width: 8, height: 8)
                    Text("Ghost Traffic").font(.caption).foregroundColor(.white)

                    Circle().fill(Color(red: 0.6, green: 0, blue: 1)).frame(width: 8, height: 8)
                    Text("AI Hypothesis").font(.caption).foregroundColor(.white)
                }
                .padding()
                .background(.thinMaterial)
                .cornerRadius(8)
                .padding(.bottom, 20)
            }
        }
    }
}
