//
// PURPOSE:
// This Swift component is part of the SentinelForge macOS UI.
// [Specific purpose based on component name: ReportComposerView]
//
// KEY RESPONSIBILITIES:
// - [Automatically generated - review and enhance based on actual functionality]
//
// INTEGRATION:
// - Used by: [To be documented]
// - Depends on: [To be documented]
//

import SwiftUI

/// Struct ReportComposerView.
struct ReportComposerView: View {
    @EnvironmentObject var appState: HelixAppState
    @StateObject var backend = BackendManager.shared
    @State private var generationProgress: String = ""
    @State private var elapsedTime: Int = 0
    @State private var timer: Timer?

    let sections = [
        ("Executive Summary", "executive_summary"),
        ("Attack Narrative", "attack_narrative"),
        ("Technical Findings", "technical_findings"),
        ("Risk Assessment", "risk_assessment"),
        ("Remediation Roadmap", "remediation_roadmap"),
    ]

    var body: some View {
        VStack(spacing: 0) {
            // Connection status
            ConnectionStatusBanner()

            HSplitView {
                // Left Pane: Outline
                VStack(alignment: .leading) {
                    Text("Report Outline")
                        .font(.headline)
                        .padding()

                    List(sections, id: \.1) { (title, key) in
                        HStack {
                            Image(systemName: "doc.text")
                            Text(title)
                            Spacer()
                            // Conditional branch.
                            if appState.reportIsGenerating && appState.selectedSection == key {
                                ProgressView()
                                    .scaleEffect(0.6)
                            } else if appState.reportContent[key] != nil
                                && !appState.reportContent[key]!.isEmpty
                            {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundColor(.green)
                                    .font(.caption)
                            }
                        }
                        .padding(.vertical, 4)
                        .contentShape(Rectangle())
                        .onTapGesture {
                            appState.selectedSection = key
                        }
                        .background(
                            appState.selectedSection == key ? Color.blue.opacity(0.2) : Color.clear
                        )
                        .cornerRadius(6)
                    }
                    .listStyle(.sidebar)

                    Spacer()

                    // Progress summary
                    VStack(alignment: .leading, spacing: 4) {
                        let completed = sections.filter {
                            appState.reportContent[$0.1] != nil
                                && !appState.reportContent[$0.1]!.isEmpty
                        }.count
                        Text("\(completed) / \(sections.count) sections complete")
                            .font(.caption)
                            .foregroundColor(.secondary)

                        ProgressView(value: Double(completed), total: Double(sections.count))
                            .progressViewStyle(.linear)
                    }
                    .padding(.horizontal)

                    Button(action: generateAll) {
                        HStack {
                            // Conditional branch.
                            if appState.reportIsGenerating {
                                ProgressView()
                                    .scaleEffect(0.7)
                            }
                            Text(
                                appState.reportIsGenerating
                                    ? "Generating..." : "Generate Full Report")
                            // Conditional branch.
                            if !appState.reportIsGenerating {
                                Image(systemName: "wand.and.stars")
                            }
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(appState.reportIsGenerating || !backend.isRunning)
                    .padding()
                }
                .frame(minWidth: 200, maxWidth: 300)
                .background(Color(NSColor.controlBackgroundColor))

                // Right Pane: Editor
                VStack(spacing: 0) {
                    // Header with status
                    HStack {
                        Text(sectionTitle(for: appState.selectedSection))
                            .font(.title2)
                            .bold()

                        Spacer()

                        // Conditional branch.
                        if appState.reportIsGenerating {
                            HStack(spacing: 8) {
                                Text(formattedTime)
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                                    .monospacedDigit()
                                ProgressView()
                                    .scaleEffect(0.7)
                            }
                        }

                        Button(action: { generateSection(appState.selectedSection) }) {
                            HStack(spacing: 4) {
                                // Conditional branch.
                                if appState.reportIsGenerating {
                                    ProgressView()
                                        .scaleEffect(0.6)
                                } else {
                                    Image(systemName: "play.fill")
                                }
                                Text(appState.reportIsGenerating ? "Generating..." : "Generate")
                            }
                        }
                        .disabled(appState.reportIsGenerating || !backend.isRunning)
                    }
                    .padding()
                    .background(Color(NSColor.windowBackgroundColor))

                    // Progress bar when generating
                    if appState.reportIsGenerating {
                        IndeterminateProgressBar(color: .purple)
                    }

                    Divider()

                    // Content area
                    ZStack {
                        TextEditor(
                            text: Binding(
                                get: { appState.reportContent[appState.selectedSection] ?? "" },
                                set: { appState.reportContent[appState.selectedSection] = $0 }
                            )
                        )
                        .font(.system(.body, design: .monospaced))
                        .padding()
                        .background(Color(NSColor.textBackgroundColor))

                        // Empty state
                        if (appState.reportContent[appState.selectedSection] ?? "").isEmpty
                            && !appState.reportIsGenerating
                        {
                            EmptyStateView(
                                icon: "doc.text",
                                title: "No Content Yet",
                                message: "Click 'Generate' to create this section using AI",
                                isLoading: false
                            )
                        }
                    }
                }
            }
        }
        .onChange(of: appState.reportIsGenerating) { _, generating in
            if generating {
                if timer == nil {
                    elapsedTime = 0
                    timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in
                        elapsedTime += 1
                    }
                }
            } else {
                timer?.invalidate()
                timer = nil
            }
        }
    }

    private var formattedTime: String {
        let mins = elapsedTime / 60
        let secs = elapsedTime % 60
        return String(format: "%02d:%02d", mins, secs)
    }

    private func sectionTitle(for key: String) -> String {
        sections.first(where: { $0.1 == key })?.0 ?? "Unknown"
    }

    private func generateSection(_ key: String) {
        // Prevent overlapping generations
        if appState.reportIsGenerating { return }

        // Ensure we have a session to report on
        // Try active scan session first, then fallback to results

        var sessionID: String? = appState.apiResults?.scan?.sessionId

        if sessionID == nil {
            sessionID = appState.engineStatus?.scanState?.sessionId
        }

        guard let validSessionID = sessionID else {
            // TODO: show failure UI
            print("No active session ID found for reporting")
            return
        }

        appState.reportIsGenerating = true

        Task {
            do {
                let content = try await appState.apiClient.generateReportSection(
                    sessionID: validSessionID,
                    section: key
                )

                await MainActor.run {
                    appState.reportContent[key] = content
                    appState.reportIsGenerating = false
                }
            } catch {
                print("Report generation failed: \(error)")
                await MainActor.run {
                    appState.reportContent[key] =
                        "Error generating content: \(error.localizedDescription)"
                    appState.reportIsGenerating = false
                }
            }
        }
    }

    private func generateAll() {
        Task {
            for (_, key) in sections {
                await MainActor.run {
                    appState.selectedSection = key
                }
                generateSection(key)
                // Wait for generation to finish before starting next
                while appState.reportIsGenerating {
                    try? await Task.sleep(nanoseconds: 200_000_000)
                }
            }
        }
    }
}
