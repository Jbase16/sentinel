import SwiftUI

struct ReportComposerView: View {
    @EnvironmentObject var appState: HelixAppState
    @StateObject var backend = BackendManager.shared
    @State private var selectedSection: String = "executive_summary"
    @State private var reportContent: [String: String] = [:]
    @State private var isGenerating: Bool = false
    @State private var generationProgress: String = ""
    @State private var elapsedTime: Int = 0
    @State private var timer: Timer?
    
    let sections = [
        ("Executive Summary", "executive_summary"),
        ("Attack Narrative", "attack_narrative"),
        ("Technical Findings", "technical_findings"),
        ("Risk Assessment", "risk_assessment"),
        ("Remediation Roadmap", "remediation_roadmap")
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
                            if isGenerating && selectedSection == key {
                                ProgressView()
                                    .scaleEffect(0.6)
                            } else if reportContent[key] != nil && !reportContent[key]!.isEmpty {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundColor(.green)
                                    .font(.caption)
                            }
                        }
                        .padding(.vertical, 4)
                        .contentShape(Rectangle())
                        .onTapGesture {
                            selectedSection = key
                        }
                        .background(selectedSection == key ? Color.blue.opacity(0.2) : Color.clear)
                        .cornerRadius(6)
                    }
                    .listStyle(.sidebar)
                    
                    Spacer()
                    
                    // Progress summary
                    VStack(alignment: .leading, spacing: 4) {
                        let completed = sections.filter { reportContent[$0.1] != nil && !reportContent[$0.1]!.isEmpty }.count
                        Text("\(completed) / \(sections.count) sections complete")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        
                        ProgressView(value: Double(completed), total: Double(sections.count))
                            .progressViewStyle(.linear)
                    }
                    .padding(.horizontal)
                    
                    Button(action: generateAll) {
                        HStack {
                            if isGenerating {
                                ProgressView()
                                    .scaleEffect(0.7)
                            }
                            Text(isGenerating ? "Generating..." : "Generate Full Report")
                            if !isGenerating {
                                Image(systemName: "wand.and.stars")
                            }
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(isGenerating || !backend.isRunning)
                    .padding()
                }
                .frame(minWidth: 200, maxWidth: 300)
                .background(Color(NSColor.controlBackgroundColor))
                
                // Right Pane: Editor
                VStack(spacing: 0) {
                    // Header with status
                    HStack {
                        Text(sectionTitle(for: selectedSection))
                            .font(.title2)
                            .bold()
                        
                        Spacer()
                        
                        if isGenerating {
                            HStack(spacing: 8) {
                                Text(formattedTime)
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                                    .monospacedDigit()
                                ProgressView()
                                    .scaleEffect(0.7)
                            }
                        }
                        
                        Button(action: { generateSection(selectedSection) }) {
                            HStack(spacing: 4) {
                                if isGenerating {
                                    ProgressView()
                                        .scaleEffect(0.6)
                                } else {
                                    Image(systemName: "play.fill")
                                }
                                Text(isGenerating ? "Generating..." : "Generate")
                            }
                        }
                        .disabled(isGenerating || !backend.isRunning)
                    }
                    .padding()
                    .background(Color(NSColor.windowBackgroundColor))
                    
                    // Progress bar when generating
                    if isGenerating {
                        IndeterminateProgressBar(color: .purple)
                    }
                    
                    Divider()
                    
                    // Content area
                    ZStack {
                        TextEditor(text: Binding(
                            get: { reportContent[selectedSection] ?? "" },
                            set: { reportContent[selectedSection] = $0 }
                        ))
                        .font(.system(.body, design: .monospaced))
                        .padding()
                        .background(Color(NSColor.textBackgroundColor))
                        
                        // Empty state
                        if (reportContent[selectedSection] ?? "").isEmpty && !isGenerating {
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
    }
    
    private var formattedTime: String {
        let mins = elapsedTime / 60
        let secs = elapsedTime % 60
        return String(format: "%02d:%02d", mins, secs)
    }
    
    private func sectionTitle(for key: String) -> String {
        sections.first(where: { $0.1 == key })?.0 ?? "Unknown"
    }
    
    private func generateSection(_ section: String) {
        isGenerating = true
        elapsedTime = 0
        reportContent[section] = "" // Clear previous content
        
        // Start timer
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in
            elapsedTime += 1
        }
        
        Task {
            let client = SentinelAPIClient()
            do {
                for try await chunk in client.streamReportSection(section: section) {
                    await MainActor.run {
                        reportContent[section, default: ""] += chunk
                    }
                }
            } catch {
                await MainActor.run {
                    reportContent[section] = "Error generating report: \(error.localizedDescription)"
                }
            }
            await MainActor.run {
                isGenerating = false
                timer?.invalidate()
                timer = nil
            }
        }
    }
    
    private func generateAll() {
        Task {
            for (_, key) in sections {
                selectedSection = key
                // Sequential generation to avoid overwhelming the backend
                // In production, you might parallelize this or use a single "full report" endpoint
                isGenerating = true
                reportContent[key] = ""
                let client = SentinelAPIClient()
                for try await chunk in client.streamReportSection(section: key) {
                    await MainActor.run {
                        reportContent[key, default: ""] += chunk
                    }
                }
                isGenerating = false
            }
        }
    }
}
