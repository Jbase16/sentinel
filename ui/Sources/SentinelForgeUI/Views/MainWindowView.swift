import SwiftUI

struct MainWindowView: View {
    @EnvironmentObject var appState: HelixAppState
    @State private var selection: SidebarItem? = .dashboard
    
    enum SidebarItem: String, Identifiable, CaseIterable {
                case dashboard = "Dashboard"
                case scan = "Target Scan"
                case graph = "Attack Graph"
                case report = "Report Composer"
                case chat = "AI Assistant"
                
                var id: String { rawValue }
                
                var icon: String {
                    switch self {
                    case .dashboard: return "gauge"
                    case .scan: return "dot.scope"
                    case .graph: return "network"
                    case .report: return "doc.text.fill"
                    case .chat: return "bubble.left.and.bubble.right.fill"
                    }
                }
            }
        
            var body: some View {
                NavigationSplitView {
                    List(SidebarItem.allCases, selection: $selection) { item in
                        NavigationLink(value: item) {
                            Label(item.rawValue, systemImage: item.icon)
                                .padding(.vertical, 4)
                        }
                    }
                    .listStyle(.sidebar)
                    .navigationSplitViewColumnWidth(min: 200, ideal: 220)
                    
                    Spacer()
                    
                    // Mini Status Footer in Sidebar
                    VStack(alignment: .leading, spacing: 4) {
                        Divider()
                        if let ai = appState.aiStatus {
                            Label {
                                Text(ai.model ?? "Unknown Model")
                                    .font(.caption)
                            } icon: {
                                Circle()
                                    .fill(ai.connected ? Color.green : Color.red)
                                    .frame(width: 6, height: 6)
                            }
                            .padding(.horizontal)
                            .padding(.top, 8)
                        }
                    }
                    .padding(.bottom)
                    
                } detail: {
                    switch selection {
                    case .dashboard:
                        DashboardView()
                    case .scan:
                        ScanControlView()
                    case .graph:
                        NetworkGraphView()
                    case .report:
                        ReportComposerView()
                    case .chat:
                        ChatView()
                    case .none:
                        Text("Select an item")
                    }
                }
                        .frame(minWidth: 900, minHeight: 600)
                        .onAppear {
                            print("MainWindowView appeared")
                            // Safely kick off streams when the UI is actually visible
                            appState.startEventStream()
                            appState.refreshStatus()
                        }
                    }
                }
                