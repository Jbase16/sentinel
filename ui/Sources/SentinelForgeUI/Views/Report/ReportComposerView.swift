import SwiftUI

struct ReportComposerView: View {
    @EnvironmentObject var appState: HelixAppState
    @State private var selectedSection: String = "executive_summary"
    @State private var reportContent: [String: String] = [:]
    @State private var isGenerating: Bool = false
    
    let sections = [
        ("Executive Summary", "executive_summary"),
        ("Attack Narrative", "attack_narrative"),
        ("Technical Findings", "technical_findings"),
        ("Risk Assessment", "risk_assessment"),
        ("Remediation Roadmap", "remediation_roadmap")
    ]
    
    var body: some View {
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
                        if reportContent[key] != nil {
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
                
                Button(action: generateAll) {
                    Label("Generate Full Report", systemImage: "wand.and.stars")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .padding()
            }
            .frame(minWidth: 200, maxWidth: 300)
            .background(Color(NSColor.controlBackgroundColor))
            
            // Right Pane: Editor
            VStack(spacing: 0) {
                HStack {
                    Text(sectionTitle(for: selectedSection))
                        .font(.title2)
                        .bold()
                    Spacer()
                    Button(action: { generateSection(selectedSection) }) {
                        Label(isGenerating ? "Generating..." : "Generate Section", systemImage: "play.fill")
                    }
                    .disabled(isGenerating)
                }
                .padding()
                .background(Color(NSColor.windowBackgroundColor))
                
                Divider()
                
                TextEditor(text: Binding(
                    get: { reportContent[selectedSection] ?? "" },
                    set: { reportContent[selectedSection] = $0 }
                ))
                .font(.system(.body, design: .monospaced))
                .padding()
                .background(Color(NSColor.textBackgroundColor))
            }
        }
    }
    
    private func sectionTitle(for key: String) -> String {
        sections.first(where: { $0.1 == key })?.0 ?? "Unknown"
    }
    
    private func generateSection(_ section: String) {
        isGenerating = true
        reportContent[section] = "" // Clear previous content
        
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
