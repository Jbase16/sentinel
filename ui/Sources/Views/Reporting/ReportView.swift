import SwiftUI

struct ReportView: View {
    @EnvironmentObject var appState: HelixAppState

    @State private var selectedTab: Int = 0
    @State private var target: String = ""
    @State private var scope: String = ""

    var body: some View {
        VStack(spacing: 0) {
            // Header / Controls
            HStack(spacing: 12) {
                Picker("Mode", selection: $selectedTab) {
                    Text("Report").tag(0)
                    Text("Proof Lab").tag(1)
                }
                .pickerStyle(.segmented)
                .frame(width: 200)

                Divider().frame(height: 20)

                TextField("Target (e.g. example.com)", text: $target)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 200)

                Button("Generate Report") {
                    Task {
                        let s = scope.trimmingCharacters(in: .whitespacesAndNewlines)
                        await appState.generateReport(
                            target: target, scope: s.isEmpty ? nil : s, format: "markdown")
                        selectedTab = 0
                    }
                }
                .disabled(target.isEmpty)
                .keyboardShortcut(.return, modifiers: [.command])

                Spacer()

                if selectedTab == 0 && !appState.activeReportMarkdown.isEmpty {
                    Button("Copy Markdown") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(
                            appState.activeReportMarkdown, forType: .string)
                    }
                }
            }
            .padding()
            .background(Color(nsColor: .controlBackgroundColor))
            .overlay(
                Rectangle().frame(height: 1).foregroundColor(Color(nsColor: .separatorColor)),
                alignment: .bottom)

            // Content
            if selectedTab == 0 {
                // MARK: - Markdown Report View
                ScrollView {
                    Text(
                        appState.activeReportMarkdown.isEmpty
                            ? "Generates a comprehensive Markdown report including findings and attack paths."
                            : appState.activeReportMarkdown
                    )
                    .font(.system(.body, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
                    .padding()
                }
            } else {
                // MARK: - Proof Lab (PoC)
                HSplitView {
                    // Left: Findings List
                    VStack(alignment: .leading) {
                        Text("Available Findings")
                            .font(.headline)
                            .padding(.horizontal)
                            .padding(.top)

                        List(appState.apiResults?.findings ?? []) { finding in
                            HStack {
                                VStack(alignment: .leading) {
                                    Text(finding.title ?? "Untitled Finding").font(
                                        .system(size: 13, weight: .medium))
                                    Text(finding.severity).font(.caption).foregroundColor(
                                        .secondary)
                                }
                                Spacer()
                                Button("Gen PoC") {
                                    Task {
                                        await appState.fetchPoC(findingId: finding.id)
                                    }
                                }
                                .buttonStyle(.borderedProminent)
                                .controlSize(.small)
                            }
                            .padding(.vertical, 4)
                        }
                    }
                    .frame(minWidth: 250, maxWidth: 350)

                    // Right: PoC Output
                    ScrollView {
                        VStack(alignment: .leading, spacing: 16) {
                            HStack {
                                Text("Proof of Concept Payloads")
                                    .font(.headline)
                                Spacer()
                                if !appState.activePoCByFindingId.isEmpty {
                                    Button("Clear Lab") {
                                        appState.activePoCByFindingId.removeAll()
                                    }
                                    .buttonStyle(.borderless)
                                    .controlSize(.small)
                                }
                            }

                            if appState.activePoCByFindingId.isEmpty {
                                Text("Select a finding to generate a safe verification payload.")
                                    .foregroundStyle(.secondary)
                                    .padding(.top, 20)
                            } else {
                                ForEach(appState.activePoCByFindingId.keys.sorted(), id: \.self) {
                                    fid in
                                    if let poc = appState.activePoCByFindingId[fid] {
                                        PoCCard(poc: poc)
                                    }
                                }
                            }
                        }
                        .padding()
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            }
        }
    }
}

struct PoCCard: View {
    let poc: PoCArtifactDTO

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(poc.title)
                    .font(.headline)
                Spacer()
                if poc.safe {
                    Text("SAFE").font(.caption).bold().padding(4).background(
                        Color.green.opacity(0.2)
                    ).cornerRadius(4)
                } else {
                    Text("UNSAFE").font(.caption).bold().padding(4).background(
                        Color.red.opacity(0.2)
                    ).cornerRadius(4)
                }
            }

            Text("Evidence ID: \(poc.finding_id)")
                .font(.caption)
                .foregroundStyle(.secondary)

            Divider()

            ForEach(poc.commands, id: \.self) { cmd in
                HStack {
                    Text(cmd)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                    Spacer()
                    Button(action: {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(cmd, forType: .string)
                    }) {
                        Image(systemName: "doc.on.doc")
                    }
                    .buttonStyle(.plain)
                }
                .padding(8)
                .background(Color.black.opacity(0.3))
                .cornerRadius(4)
            }

            if !poc.notes.isEmpty {
                VStack(alignment: .leading) {
                    ForEach(poc.notes, id: \.self) { note in
                        Text("• \(note)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(.top, 4)
            }
        }
        .padding()
        .background(Color(nsColor: .controlBackgroundColor))
        .cornerRadius(8)
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.gray.opacity(0.3), lineWidth: 1))
    }
}
