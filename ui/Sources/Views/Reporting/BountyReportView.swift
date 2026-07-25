//
// BountyReportView.swift
// SentinelForge
//
// Displays the bug-bounty report fetched from GET /v1/scans/bounty-report.
// Shows per-finding cards with CVSS score, severity badge, steps, and
// copy-to-clipboard for each finding's individual Markdown.
//

import SwiftUI

/// Main view for the "Bounty Report" tab inside ReportView.
struct BountyReportView: View {
    @EnvironmentObject var appState: HelixAppState

    @State private var selectedFindingId: String? = nil
    @State private var showFullMarkdown: Bool = false

    // Filters
    @State private var hideKnownDupes: Bool = false

    private var displayedReports: [BountyFindingReport] {
        guard let reports = appState.bountyReport?.reports else { return [] }
        if hideKnownDupes {
            return reports.filter { $0.duplicateInfo?.isDuplicate != true }
        }
        return reports
    }

    var body: some View {
        HSplitView {
            // ── Left pane: report list ──
            VStack(spacing: 0) {
                controlBar
                Divider()
                if appState.bountyReportIsLoading {
                    loadingView
                } else if let err = appState.bountyReportError {
                    errorView(err)
                } else if displayedReports.isEmpty {
                    emptyView
                } else {
                    reportList
                }
            }
            .frame(minWidth: 260, maxWidth: 340)

            // ── Right pane: selected finding detail ──
            detailPane
        }
    }

    // MARK: - Control Bar

    private var controlBar: some View {
        VStack(spacing: 8) {
            HStack(spacing: 8) {
                // Refresh button
                Button(action: { appState.refreshBountyReport() }) {
                    Label("Refresh", systemImage: "arrow.clockwise")
                        .font(.caption)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.small)
                .disabled(appState.bountyReportIsLoading)

                Spacer()

                // Copy full report
                if appState.bountyReport != nil {
                    Button(action: copyFullReport) {
                        Label("Copy All", systemImage: "doc.on.doc")
                            .font(.caption)
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }
            }

            HStack(spacing: 8) {
                // Platform picker
                Picker("Platform", selection: $appState.bountyPlatform) {
                    Text("HackerOne").tag("hackerone")
                    Text("Bugcrowd").tag("bugcrowd")
                }
                .pickerStyle(.menu)
                .font(.caption)
                .frame(maxWidth: 120)

                // Min severity picker
                Picker("Min severity", selection: $appState.bountyMinSeverity) {
                    Text("Low+").tag("LOW")
                    Text("Medium+").tag("MEDIUM")
                    Text("High+").tag("HIGH")
                    Text("Critical").tag("CRITICAL")
                }
                .pickerStyle(.menu)
                .font(.caption)
                .frame(maxWidth: 100)

                Spacer()

                Toggle("Hide dupes", isOn: $hideKnownDupes)
                    .toggleStyle(.checkbox)
                    .font(.caption)
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background(Color(NSColor.controlBackgroundColor))
    }

    // MARK: - Report List

    private var reportList: some View {
        List(selection: $selectedFindingId) {
            let count = appState.bountyReport?.count ?? 0
            Section(header:
                HStack {
                    Text("\(displayedReports.count) findings")
                    if hideKnownDupes {
                        Text("(\(count) total)")
                            .foregroundColor(.secondary)
                    }
                }
                .font(.caption)
            ) {
                ForEach(displayedReports) { report in
                    BountyReportRowView(report: report)
                        .tag(report.findingId)
                }
            }
        }
        .listStyle(.sidebar)
    }

    // MARK: - Detail Pane

    private var detailPane: some View {
        Group {
            if let id = selectedFindingId,
               let report = displayedReports.first(where: { $0.findingId == id }) {
                BountyFindingDetailView(report: report)
            } else {
                VStack(spacing: 12) {
                    Image(systemName: "doc.badge.arrow.up")
                        .font(.system(size: 40))
                        .foregroundColor(.secondary)
                    Text("Select a finding to view its bounty report card.")
                        .foregroundColor(.secondary)
                    if appState.bountyReport == nil && !appState.bountyReportIsLoading {
                        Button("Generate Report") { appState.refreshBountyReport() }
                            .buttonStyle(.borderedProminent)
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
    }

    // MARK: - Utility States

    private var loadingView: some View {
        VStack(spacing: 12) {
            ProgressView()
            Text("Building bounty report…")
                .foregroundColor(.secondary)
                .font(.caption)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func errorView(_ msg: String) -> some View {
        VStack(spacing: 8) {
            Image(systemName: "exclamationmark.triangle")
                .foregroundColor(.red)
                .font(.title2)
            Text(msg)
                .font(.caption)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
            Button("Retry") { appState.refreshBountyReport() }
                .buttonStyle(.bordered)
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var emptyView: some View {
        VStack(spacing: 12) {
            Image(systemName: "checkmark.shield")
                .foregroundColor(.green)
                .font(.title2)
            Text("No reportable findings at this severity threshold.")
                .foregroundColor(.secondary)
                .font(.caption)
                .multilineTextAlignment(.center)
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Actions

    private func copyFullReport() {
        guard let md = appState.bountyReport?.markdown else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(md, forType: .string)
    }
}

// MARK: - Row View

private struct BountyReportRowView: View {
    let report: BountyFindingReport

    var body: some View {
        HStack(spacing: 8) {
            // Severity dot
            Circle()
                .fill(severityColor(report.severity))
                .frame(width: 8, height: 8)

            VStack(alignment: .leading, spacing: 2) {
                Text(report.title)
                    .font(.system(size: 13, weight: .medium))
                    .lineLimit(1)

                HStack(spacing: 6) {
                    if let score = report.cvssScore {
                        Text(String(format: "%.1f", score))
                            .font(.caption2)
                            .padding(.horizontal, 4)
                            .padding(.vertical, 1)
                            .background(cvssBackground(score))
                            .cornerRadius(3)
                    }
                    if let asset = report.asset {
                        Text(asset)
                            .font(.caption2)
                            .foregroundColor(.secondary)
                            .lineLimit(1)
                    }
                }
            }

            Spacer()

            // Duplicate indicator
            if report.duplicateInfo?.isDuplicate == true {
                Image(systemName: "arrow.triangle.2.circlepath")
                    .font(.caption2)
                    .foregroundColor(.purple)
                    .help(report.duplicateInfo?.annotation ?? "Known duplicate")
            }
        }
        .padding(.vertical, 3)
    }

    private func cvssBackground(_ score: Double) -> Color {
        if score >= 9.0 { return Color.red.opacity(0.25) }
        if score >= 7.0 { return Color.orange.opacity(0.25) }
        if score >= 4.0 { return Color.yellow.opacity(0.25) }
        return Color.blue.opacity(0.15)
    }
}

// MARK: - Detail View

private struct BountyFindingDetailView: View {
    let report: BountyFindingReport
    @State private var showRawMarkdown: Bool = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                // Title + action row
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(report.title)
                            .font(.title2).bold()

                        HStack(spacing: 8) {
                            SeverityPill(severity: report.severity)

                            if let score = report.cvssScore, let label = report.cvssLabel {
                                Text("\(label) \(String(format: "%.1f", score))")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }

                            if let dupe = report.duplicateInfo, dupe.isDuplicate {
                                Text(dupe.annotation ?? "DUPLICATE")
                                    .font(.caption)
                                    .foregroundColor(.purple)
                                    .padding(.horizontal, 6)
                                    .padding(.vertical, 2)
                                    .overlay(
                                        RoundedRectangle(cornerRadius: 4)
                                            .stroke(Color.purple.opacity(0.4))
                                    )
                            }
                        }
                    }

                    Spacer()

                    // Copy individual report markdown
                    Button(action: copyMarkdown) {
                        Label("Copy", systemImage: "doc.on.doc")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .help("Copy this finding's Markdown to clipboard")

                    Toggle("Raw", isOn: $showRawMarkdown)
                        .toggleStyle(.button)
                        .controlSize(.small)
                }

                if showRawMarkdown {
                    // Raw Markdown view
                    TextEditor(text: .constant(report.markdown))
                        .font(.system(size: 11, design: .monospaced))
                        .frame(minHeight: 400)
                        .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.gray.opacity(0.2)))
                } else {
                    // Structured card view

                    if let asset = report.asset {
                        InfoRow(label: "Asset", value: asset, monospaced: true)
                    }

                    if let vector = report.cvssVector {
                        InfoRow(label: "CVSS Vector", value: vector, monospaced: true)
                    }

                    if let summary = report.summary {
                        SectionBlock(title: "Summary", content: summary)
                    }

                    if let steps = report.stepsToReproduce, !steps.isEmpty {
                        VStack(alignment: .leading, spacing: 6) {
                            Text("Steps to Reproduce")
                                .font(.subheadline).bold()
                            ForEach(Array(steps.enumerated()), id: \.offset) { idx, step in
                                HStack(alignment: .top, spacing: 8) {
                                    Text("\(idx + 1).")
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                        .frame(width: 20, alignment: .trailing)
                                    Text(step)
                                        .font(.caption)
                                        .textSelection(.enabled)
                                }
                            }
                        }
                        .padding()
                        .background(Color(NSColor.controlBackgroundColor))
                        .cornerRadius(8)
                    }

                    if let impact = report.impact {
                        SectionBlock(title: "Impact", content: impact)
                    }

                    if let rem = report.remediation {
                        SectionBlock(title: "Remediation", content: rem)
                    }
                }
            }
            .padding()
        }
    }

    private func copyMarkdown() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(report.markdown, forType: .string)
    }
}

// MARK: - Helpers

private struct SeverityPill: View {
    let severity: String

    var body: some View {
        Text(severity.uppercased())
            .font(.system(size: 10, weight: .black, design: .monospaced))
            .foregroundColor(.white)
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .background(severityColor(severity))
            .cornerRadius(4)
    }
}

private struct InfoRow: View {
    let label: String
    let value: String
    var monospaced: Bool = false

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Text(label + ":")
                .font(.caption).bold()
                .foregroundColor(.secondary)
                .frame(width: 90, alignment: .trailing)
            Text(value)
                .font(monospaced ? .system(size: 11, design: .monospaced) : .caption)
                .textSelection(.enabled)
            Spacer()
        }
    }
}

private struct SectionBlock: View {
    let title: String
    let content: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.subheadline).bold()
            Text(content)
                .font(.callout)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(8)
    }
}

// Shared helper — returns the right color for a severity string.
func severityColor(_ severity: String) -> Color {
    switch severity.uppercased() {
    case "CRITICAL": return Color(red: 0.8, green: 0.1, blue: 0.1)
    case "HIGH":     return .orange
    case "MEDIUM":   return Color(red: 0.8, green: 0.6, blue: 0.0)
    case "LOW":      return .blue
    default:         return .gray
    }
}
