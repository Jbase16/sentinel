//
//  DecisionStreamView.swift
//  SentinelForgeUI
//
//  Visualizes the live stream of Strategos decisions.
//

import SwiftUI

struct DecisionStreamView: View {
    let decisions: [Decision]

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Header
            HStack {
                Image(systemName: "brain.head.profile")
                    .foregroundColor(.purple)
                Text("Reasoning Stream")
                    .font(.headline)
                Spacer()
                Text("\(decisions.count) decisions")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            .padding()
            .background(Color(NSColor.controlBackgroundColor))

            Divider()

            if decisions.isEmpty {
                Text("No decisions recorded yet.")
                    .foregroundColor(.secondary)
                    .italic()
                    .padding()
                    .frame(maxWidth: .infinity, alignment: .center)
            } else {
                List {
                    ForEach(decisions) { decision in
                        DecisionRow(decision: decision)
                            .padding(.vertical, 4)
                    }
                }
                .listStyle(.plain)
                .frame(minHeight: 200, maxHeight: 400)  // Constrain height in dashboard
            }
        }
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(12)
        .shadow(color: Color.black.opacity(0.1), radius: 2, x: 0, y: 1)
    }
}

struct DecisionRow: View {
    let decision: Decision
    @State private var isExpanded: Bool = false

    // Highlight important decision types
    var iconName: String {
        switch decision.type {
        case "assessment": return "stethoscope"
        case "tool_selection": return "hammer.fill"
        case "intent_transition": return "arrow.triangle.branch"
        case "phase_transition": return "flag.fill"
        case "resource_allocation": return "creditcard.fill"
        default: return "brain"
        }
    }

    var iconColor: Color {
        switch decision.type {
        case "assessment": return .blue
        case "tool_selection": return .orange
        case "intent_transition": return .purple
        case "phase_transition": return .green
        case "resource_allocation": return .yellow
        default: return .gray
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            // Top Row (Always Visible)
            HStack(alignment: .top) {
                Image(systemName: iconName)
                    .foregroundColor(iconColor)
                    .frame(width: 20)

                VStack(alignment: .leading, spacing: 2) {
                    HStack {
                        Text(decision.type.uppercased())
                            .font(.caption2)
                            .fontWeight(.bold)
                            .foregroundColor(.secondary)

                        // Confidence Badge
                        if decision.confidence < 0.9 {
                            Text(String(format: "%.0f%% Conf", decision.confidence * 100))
                                .font(.caption2)
                                .padding(.horizontal, 4)
                                .background(Color.yellow.opacity(0.2))
                                .cornerRadius(4)
                        }

                        Spacer()

                        Text(decision.timestamp, style: .time)
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }

                    Text(decision.selectedAction)
                        .font(.system(.body, design: .monospaced))
                        .fontWeight(.medium)
                }

                Button(action: { withAnimation { isExpanded.toggle() } }) {
                    Image(systemName: "chevron.down")
                        .rotationEffect(.degrees(isExpanded ? 180 : 0))
                        .foregroundColor(.secondary)
                }
                .buttonStyle(.plain)
            }

            // Expanded Details
            if isExpanded {
                VStack(alignment: .leading, spacing: 8) {
                    Divider()

                    // Rationale
                    if !decision.rationale.isEmpty {
                        VStack(alignment: .leading) {
                            Text("RATIONALE")
                                .font(.caption2)
                                .foregroundColor(.secondary)
                            Text(decision.rationale)
                                .font(.callout)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }

                    // Alternatives / Suppressed
                    if let suppressed = decision.suppressed, !suppressed.isEmpty {
                        VStack(alignment: .leading) {
                            Text("SUPPRESSED")
                                .font(.caption2)
                                .foregroundColor(.red.opacity(0.8))
                            ForEach(suppressed, id: \.self) { alt in
                                Text("• \(alt)")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                        }
                    }

                    // Evidence (if any keys exist)
                    if let evidence = decision.evidence, !evidence.isEmpty {
                        VStack(alignment: .leading) {
                            Text("EVIDENCE")
                                .font(.caption2)
                                .foregroundColor(.secondary)

                            ForEach(evidence.keys.sorted(), id: \.self) { key in
                                HStack(alignment: .top) {
                                    Text("\(key):")
                                        .font(.caption)
                                        .bold()

                                    let rawValue = String(describing: evidence[key]?.value ?? "")
                                    let displayValue =
                                        rawValue.count > 200
                                        ? String(rawValue.prefix(200)) + "..." : rawValue

                                    Text(displayValue)
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                        .lineLimit(3)
                                }
                            }
                        }
                    }
                }
                .padding(.leading, 28)  // Indent content
                .padding(.top, 4)
            }
        }
        .padding(8)
        .background(isExpanded ? Color.gray.opacity(0.05) : Color.clear)
        .cornerRadius(8)
    }
}
