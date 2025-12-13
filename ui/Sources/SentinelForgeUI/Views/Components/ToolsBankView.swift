import SwiftUI

struct ToolsBankView: View {
    @EnvironmentObject var appState: HelixAppState
    @State private var selectedMissing: Set<String> = []
    @State private var installing = false
    @State private var lastResults: [InstallResult] = []

    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                Text("Tool Bank")
                    .font(.title2).bold()
                Spacer()
                Button(action: installSelected) {
                    Label("Install Selected", systemImage: "arrow.down.circle.fill")
                }
                .disabled(selectedMissing.isEmpty || installing)
            }
            .padding(.bottom, 8)

            HStack(alignment: .top) {
                VStack(alignment: .leading) {
                    Text("Installed (") + Text("\(appState.engineStatus?.tools?.installed.count ?? 0)") + Text(")")
                    List(appState.engineStatus?.tools?.installed ?? [], id: \.self) { name in
                        HStack { Image(systemName: "checkmark.circle.fill").foregroundColor(.green); Text(name) }
                    }
                }.frame(maxWidth: .infinity)

                VStack(alignment: .leading) {
                    Text("Missing (") + Text("\(appState.engineStatus?.tools?.missing.count ?? 0)") + Text(") – select to install")
                    List(selection: $selectedMissing) {
                        ForEach(appState.engineStatus?.tools?.missing ?? [], id: \.self) { name in
                            HStack { Image(systemName: selectedMissing.contains(name) ? "checkmark.square" : "square"); Text(name) }
                                .contentShape(Rectangle())
                                .onTapGesture { toggle(name) }
                        }
                    }
                }.frame(maxWidth: .infinity)
            }

            if !lastResults.isEmpty {
                Divider().padding(.vertical, 8)
                Text("Last Installation Results")
                    .font(.headline)
                List(lastResults) { res in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text(res.tool).bold()
                            Spacer()
                            Text(res.status.uppercased())
                                .font(.caption)
                                .foregroundColor(res.status == "installed" ? .green : .orange)
                        }
                        if let msg = res.message, !msg.isEmpty {
                            Text(msg).font(.caption2).foregroundColor(.secondary).lineLimit(3)
                        }
                    }
                }.frame(minHeight: 120)
            }
        }
        .padding()
        .onAppear { appState.refreshStatus() }
    }

    private func toggle(_ name: String) {
        if selectedMissing.contains(name) { selectedMissing.remove(name) } else { selectedMissing.insert(name) }
    }

    private func installSelected() {
        guard !selectedMissing.isEmpty else { return }
        installing = true
        Task { @MainActor in
            do {
                let results = try await appState.apiClient.installTools(Array(selectedMissing))
                self.lastResults = results
                self.selectedMissing.removeAll()
                // Refresh status to update installed/missing lists
                self.appState.refreshStatus()
            } catch {
                self.lastResults = [InstallResult(tool: "(batch)", status: "error", message: error.localizedDescription)]
            }
            installing = false
        }
    }
}