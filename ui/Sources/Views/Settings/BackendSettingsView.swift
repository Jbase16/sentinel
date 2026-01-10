//
// PURPOSE:
// Backend configuration UI for selecting runtime and backend path.
//

import AppKit
import SwiftUI

struct BackendSettingsView: View {
    @AppStorage(BackendConfigKeys.backendRuntime) private var runtimeSelection =
        BackendRuntimeSelection.auto.rawValue
    @AppStorage(BackendConfigKeys.backendPath) private var backendPath = ""

    @Environment(\.dismiss) private var dismiss

    private var selectedRuntime: BackendRuntimeSelection {
        BackendRuntimeSelection(rawValue: runtimeSelection) ?? .auto
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Backend Configuration")
                .font(.headline)

            VStack(alignment: .leading, spacing: 8) {
                Text("Runtime")
                    .font(.subheadline)
                    .foregroundColor(.secondary)

                Picker("Runtime", selection: $runtimeSelection) {
                    ForEach(BackendRuntimeSelection.allCases) { option in
                        Text(option.label).tag(option.rawValue)
                    }
                }
                .pickerStyle(.segmented)
            }

            VStack(alignment: .leading, spacing: 8) {
                Text("Backend Path")
                    .font(.subheadline)
                    .foregroundColor(.secondary)

                HStack {
                    TextField("/path/to/sentinelforge", text: $backendPath)
                        .textFieldStyle(.roundedBorder)
                        .disabled(selectedRuntime != .custom)

                    Button("Browse") {
                        chooseBackendPath()
                    }
                    .disabled(selectedRuntime != .custom)
                }

                Text(backendPathHelperText())
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Spacer()

            HStack {
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 480, height: 260)
    }

    private func backendPathHelperText() -> String {
        switch selectedRuntime {
        case .auto:
            return "Auto mode searches common dev locations for core/server/api.py."
        case .custom:
            return "Custom path must contain core/server/api.py."
        case .bundled:
            return "Bundled mode uses the runtime shipped inside the app bundle."
        }
    }

    private func chooseBackendPath() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.prompt = "Select"
        panel.message = "Choose the Sentinel backend root folder."

        if panel.runModal() == .OK, let url = panel.url {
            backendPath = url.path
        }
    }
}

#Preview {
    BackendSettingsView()
}
