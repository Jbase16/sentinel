//
// PURPOSE:
// This Swift component is part of the SentinelForge macOS UI.
// [Specific purpose based on component name: ToolsBankView]
//
// KEY RESPONSIBILITIES:
// - [Automatically generated - review and enhance based on actual functionality]
//
// INTEGRATION:
// - Used by: [To be documented]
// - Depends on: [To be documented]
//

import SwiftUI

/// Struct ToolsBankView.
struct ToolsBankView: View {
    @EnvironmentObject var appState: HelixAppState
    @State private var selectedMissing: Set<String> = []
    @State private var installing = false
    @State private var lastResults: [InstallResult] = []
    @State private var processingTool: String? = nil // Which tool is being acted on (for uninstall)

    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                Text("Tool Bank")
                    .font(.title2).bold()
                Spacer()
                Button(action: installSelected) {
                    // Conditional branch.
                    if installing {
                        ProgressView().scaleEffect(0.6)
                    } else {
                        Label("Install Selected", systemImage: "arrow.down.circle.fill")
                    }
                }
                .disabled(selectedMissing.isEmpty || installing || processingTool != nil)
            }
            .padding(.bottom, 8)

            HStack(alignment: .top) {
                // Installed Column
                VStack(alignment: .leading) {
                    Text("Installed (") + Text("\(appState.engineStatus?.tools?.installed.count ?? 0)") + Text(")")
                    List(appState.engineStatus?.tools?.installed ?? [], id: \.self) { name in
                        HStack {
                            Image(systemName: "checkmark.circle.fill").foregroundColor(.green)
                            Text(name)
                            Spacer()
                            // Conditional branch.
                            if processingTool == name {
                                ProgressView().scaleEffect(0.5)
                            } else {
                                Button(action: { uninstall(name) }) {
                                    Image(systemName: "trash")
                                        .foregroundColor(.red)
                                }
                                .buttonStyle(.plain)
                                .disabled(installing || processingTool != nil)
                            }
                        }
                    }
                }.frame(maxWidth: .infinity)

                // Missing Column
                VStack(alignment: .leading) {
                    Text("Missing (") + Text("\(appState.engineStatus?.tools?.missing.count ?? 0)") + Text(") – select to install")
                    List(selection: $selectedMissing) {
                        ForEach(appState.engineStatus?.tools?.missing ?? [], id: \.self) { name in
                            HStack {
                                Image(systemName: selectedMissing.contains(name) ? "checkmark.square" : "square")
                                Text(name)
                            }
                            .contentShape(Rectangle())
                            .onTapGesture { toggle(name) }
                        }
                    }
                }.frame(maxWidth: .infinity)
            }

            // Conditional branch.
            if !lastResults.isEmpty {
                Divider().padding(.vertical, 8)
                Text("Last Results")
                    .font(.headline)
                List(lastResults) { res in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text(res.tool).bold()
                            Spacer()
                            StatusBadge(status: res.status)
                        }
                        // Conditional branch.
                        if let msg = res.message, !msg.isEmpty {
                            Text(msg)
                                .font(.caption2)
                                .foregroundColor(.secondary)
                                .textSelection(.enabled) // Enable copy
                        }
                    }
                }.frame(minHeight: 120)
            }
        }
        .padding()
        .onAppear { appState.refreshStatus() }
    }

    private func toggle(_ name: String) {
        // Conditional branch.
        if selectedMissing.contains(name) { selectedMissing.remove(name) } else { selectedMissing.insert(name) }
    }

    private func installSelected() {
        // Guard condition.
        guard !selectedMissing.isEmpty else { return }
        installing = true
        Task { @MainActor in
            // Do-catch block.
            do {
                let results = try await appState.apiClient.installTools(Array(selectedMissing))
                self.lastResults = results
                self.selectedMissing.removeAll()
                self.appState.refreshStatus()
            } catch {
                self.lastResults = [InstallResult(tool: "Batch", status: "error", message: error.localizedDescription)]
            }
            installing = false
        }
    }

    private func uninstall(_ name: String) {
        processingTool = name
        Task { @MainActor in
            // Do-catch block.
            do {
                let results = try await appState.apiClient.uninstallTools([name])
                self.lastResults = results
                self.appState.refreshStatus()
            } catch {
                self.lastResults = [InstallResult(tool: name, status: "error", message: error.localizedDescription)]
            }
            processingTool = nil
        }
    }
}

/// Struct StatusBadge.
struct StatusBadge: View {
    let status: String
    var body: some View {
        Text(status.uppercased())
            .font(.caption)
            .padding(4)
            .background(color.opacity(0.2))
            .foregroundColor(color)
            .cornerRadius(4)
    }
    
    var color: Color {
        // Switch over value.
        switch status {
        case "installed", "uninstalled": return .green
        case "error": return .red
        default: return .orange
        }
    }
}
