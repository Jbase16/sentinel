//
// PURPOSE:
// This Swift component is part of the SentinelForge macOS UI.
// [Specific purpose based on component name: NetworkGraphView]
//
// KEY RESPONSIBILITIES:
// - [Automatically generated - review and enhance based on actual functionality]
//
// INTEGRATION:
// - Used by: [To be documented]
// - Depends on: [To be documented]
//

import SwiftUI

/// Struct NetworkGraphView.
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

                    // Conditional branch.
                    if appState.cortexStream.isConnected {
                        Text("CORTEX STREAM :: CONNECTED")
                            .font(.custom("Courier New", size: 14))
                            .foregroundColor(.green)
                            .padding(8)
                            .background(.ultraThinMaterial)
                            .cornerRadius(4)
                    }

                    // Conditional branch.
                    if appState.eventClient.isConnected {
                        Text("EVENT STREAM :: CONNECTED")
                            .font(.custom("Courier New", size: 14))
                            .foregroundColor(.green)
                            .padding(8)
                            .background(.ultraThinMaterial)
                            .cornerRadius(4)
                    }

                    // Conditional branch.
                    if appState.isGhostActive {
                        Text("GHOST PROTOCOL :: ACTIVE")
                            .font(.custom("Courier New", size: 14))
                            .foregroundColor(.orange)
                            .padding(8)
                            .background(.ultraThinMaterial)
                            .cornerRadius(4)
                    }

                    Toggle("DECISIONS", isOn: $appState.showDecisionLayerInGraph)
                        .toggleStyle(.switch)
                        .font(.custom("Courier New", size: 11))
                        .foregroundColor(.white)
                        .padding(6)
                        .background(.ultraThinMaterial)
                        .cornerRadius(4)

                    Toggle("FILTER", isOn: $appState.hideLowSignalGraphNodes)
                        .toggleStyle(.switch)
                        .font(.custom("Courier New", size: 11))
                        .foregroundColor(.white)
                        .padding(6)
                        .background(.ultraThinMaterial)
                        .cornerRadius(4)

                    Spacer()

                    // Identity Badge
                    IdentityStatusView(appState: appState)
                        .padding(.trailing, 8)

                    Text("NODES: \(appState.cortexStream.nodes.count)")
                        .font(.custom("Courier New", size: 12))
                        .foregroundColor(.white)
                }
                .padding()

                // BREACH WARNING
                if let target = appState.activeBreachTarget {
                    VStack {
                        Text("🚨 CRITICAL BREACH DETECTED 🚨")
                            .font(.headline)  // Using standard font for safety
                            .fontWeight(.black)
                            .foregroundColor(.white)
                        Text(target)
                            .font(.subheadline)  // Using standard font
                            .foregroundColor(.white)
                    }
                    .padding()
                    .background(Color.red.opacity(0.8))
                    .cornerRadius(12)
                    .padding(.top, 20)
                    .transition(.opacity)
                }

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
        .onChange(of: appState.showDecisionLayerInGraph) {
            appState.applyGraphLayerVisibility()
            appState.fetchAnalysis()
        }
        .onChange(of: appState.hideLowSignalGraphNodes) {
            appState.applyGraphLayerVisibility()
            appState.fetchAnalysis()
        }
    }
}
