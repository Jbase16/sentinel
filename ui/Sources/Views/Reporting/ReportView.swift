import SwiftUI

struct ReportView: View {
    @EnvironmentObject var appState: HelixAppState

    @State private var target: String = ""
    @State private var scope: String = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 12) {
                TextField("Target (e.g., example.com)", text: $target)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 280)

                TextField("Scope (optional)", text: $scope)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 320)

                Button("Generate Report") {
                    Task {
                        let s = scope.trimmingCharacters(in: .whitespacesAndNewlines)
                        await appState.generateReport(
                            target: target, scope: s.isEmpty ? nil : s, format: "markdown")
                    }
                }
                .keyboardShortcut(.return, modifiers: [.command])
            }

            Divider()

            HStack(spacing: 10) {
                if let meta = appState.activeReportMeta {
                    Text("Report: \(meta.report_id)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text(meta.created_at)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    Text("No report generated yet.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Spacer()

                Button("Copy Markdown") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(appState.activeReportMarkdown, forType: .string)
                }
                .disabled(appState.activeReportMarkdown.isEmpty)
            }

            ScrollView {
                Text(
                    appState.activeReportMarkdown.isEmpty
                        ? "Generate a report to see output here." : appState.activeReportMarkdown
                )
                .font(.system(.body, design: .monospaced))
                .frame(maxWidth: .infinity, alignment: .leading)
                .textSelection(.enabled)
                .padding(.vertical, 8)
            }
        }
        .padding(16)
    }
}
