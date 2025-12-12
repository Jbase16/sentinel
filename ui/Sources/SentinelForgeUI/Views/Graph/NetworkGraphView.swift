import SwiftUI

struct NetworkGraphView: View {
    @EnvironmentObject var appState: HelixAppState
    
    var body: some View {
        ZStack {
            // The Metal View (Interactive)
            InteractiveGraphContainer()
                .edgesIgnoringSafeArea(.all)
            
            // Overlay HUD
            VStack {
                HStack {
                    Text("NEURAL INTERFACE :: LIVE")
                        .font(.custom("Courier New", size: 14))
                        .foregroundColor(.green)
                        .padding(8)
                        .background(.ultraThinMaterial)
                        .cornerRadius(4)
                    
                    Spacer()
                    
                    Text("NODES: \(appState.cortexStream.nodes.count)")
                        .font(.custom("Courier New", size: 12))
                        .foregroundColor(.white)
                }
                .padding()
                
                Spacer()
            }
        }
    }
}
