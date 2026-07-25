import SwiftUI

struct AuditFeedView: View {
    @EnvironmentObject var appState: HelixAppState
    @State private var includeLogs = false
    @State private var includeGraphStructure = false

    private var displayEvents: [GraphEvent] {
        var seen = Set<String>()
        var output: [GraphEvent] = []
        for event in appState.allEvents.reversed() {
            if !seen.insert(event.id).inserted {
                continue
            }
            if !includeLogs && event.eventType == .log {
                continue
            }
            if !includeGraphStructure {
                if event.eventType == .nodeAdded
                    || event.eventType == .nodeUpdated
                    || event.eventType == .nodeRemoved
                    || event.eventType == .edgeAdded
                    || event.eventType == .edgeUpdated
                {
                    continue
                }
            }
            output.append(event)
            if output.count >= 300 {
                break
            }
        }
        return output
    }

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Text("AUDIT FEED")
                    .font(.caption)
                    .fontWeight(.bold)
                    .foregroundColor(.gray)
                Spacer()
                Toggle("Logs", isOn: $includeLogs)
                    .toggleStyle(.switch)
                    .font(.caption2)
                    .labelsHidden()
                Text(includeLogs ? "logs:on" : "logs:off")
                    .font(.caption2)
                    .foregroundColor(.gray)
                Toggle("Graph", isOn: $includeGraphStructure)
                    .toggleStyle(.switch)
                    .font(.caption2)
                    .labelsHidden()
                Text(includeGraphStructure ? "graph:on" : "graph:off")
                    .font(.caption2)
                    .foregroundColor(.gray)
                Text("\(displayEvents.count)")
                    .font(.caption2)
                    .foregroundColor(.gray)
                Circle()
                    .fill(appState.eventClient.isConnected ? Color.green : Color.red)
                    .frame(width: 8, height: 8)
            }
            .padding()
            .background(Color.black.opacity(0.2))

            // List
            List(displayEvents) { event in
                EventRow(event: event)
            }
            .listStyle(.plain)
        }
        .background(Color(red: 0.05, green: 0.05, blue: 0.08))
    }
}

struct EventRow: View {
    let event: GraphEvent

    private var decisionType: String? {
        event.payload["decision_type"]?.stringValue
    }

    private var decisionAction: String? {
        event.payload["selected_action"]?.stringValue
    }

    private var decisionRationale: String? {
        event.payload["rationale"]?.stringValue
    }

    private var decisionEvidence: [String: Any]? {
        event.payload["evidence"]?.dictValue
    }

    var color: Color {
        switch event.eventType {
        case .findingCreated, .findingConfirmed, .findingDiscovered: return .red
        case .scanFailed, .breachDetected: return .purple
        case .scanCompleted, .exploitValidated: return .green
        case .decisionMade, .narrativeEmitted: return .blue
        case .nexusInsightFormed: return .purple
        case .log: return .gray
        case .toolStarted, .toolCompleted: return .orange
        default: return .secondary
        }
    }

    var title: String {
        switch event.eventType {
        case .toolStarted:
            return (event.payload["tool"]?.stringValue ?? "Unknown Tool").uppercased()
        case .findingCreated:
            return (event.payload["title"]?.stringValue ?? "Finding").uppercased()
        case .decisionMade:
            return (decisionType ?? "DECISION").uppercased()
        case .nexusInsightFormed:
            return (event.payload["action_type"]?.stringValue ?? "INSIGHT").uppercased()
        default:
            return event.type.uppercased()
        }
    }

    var details: String {
        switch event.eventType {
        case .toolStarted:
            return event.payload["target"]?.stringValue ?? ""
        case .findingCreated:
            return event.payload["severity"]?.stringValue ?? ""
        case .nodeAdded, .nodeUpdated, .nodeRemoved:
            let id = event.payload["node_id"]?.stringValue ?? event.payload["id"]?.stringValue ?? ""
            let t = event.payload["node_type"]?.stringValue ?? event.payload["type"]?.stringValue ?? ""
            if !t.isEmpty && !id.isEmpty { return "\(t) • \(id.prefix(10))" }
            return t.isEmpty ? String(id.prefix(16)) : t
        case .edgeAdded, .edgeUpdated:
            let src = event.payload["source"]?.stringValue ?? ""
            let dst = event.payload["target"]?.stringValue ?? ""
            if !src.isEmpty && !dst.isEmpty { return "\(src.prefix(10)) → \(dst.prefix(10))" }
            return ""
        case .scanPhaseChanged:
            return event.payload["phase"]?.stringValue ?? ""
        case .decisionMade:
            let action = decisionAction ?? ""
            if let dt = decisionType, dt == "tool_rejection",
                let evidence = decisionEvidence,
                let toolsAny = evidence["tools"] as? [Any],
                !toolsAny.isEmpty
            {
                let tools = toolsAny.prefix(8).map { "\($0)" }.joined(separator: ", ")
                return "\(action) • blocked: \(tools)" + (toolsAny.count > 8 ? "…" : "")
            }
            return action
        case .nexusInsightFormed:
            return event.payload["summary"]?.stringValue ?? ""
        case .log:
            return event.payload["line"]?.stringValue ?? event.payload["message"]?.stringValue ?? ""
        default:
            return ""
        }
    }

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: event.iconName)
                .foregroundColor(color)
                .frame(width: 20)
                .padding(.top, 2)

            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(title)
                        .font(.custom("Menlo-Bold", size: 12))
                        .foregroundColor(color)

                    if !details.isEmpty {
                        Text("• " + details.prefix(60))
                            .font(.custom("Menlo", size: 12))
                            .foregroundColor(.gray)
                            .lineLimit(1)
                    }

                    Spacer()

                    Text(Date(timeIntervalSince1970: event.timestamp), style: .time)
                        .font(.caption2)
                        .foregroundColor(.gray)
                }

                if event.eventType == .decisionMade, let rationale = decisionRationale, !rationale.isEmpty {
                    Text(rationale)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.gray)
                        .lineLimit(2)
                }

                // Payload Dump (simplified for specific types)
                if event.eventType == .toolCompleted {
                    if let budget = event.payload["budget"]?.dictValue {
                        let tokens = budget["tokens_remaining"] as? Int ?? 0
                        let max = budget["tokens_max"] as? Int ?? 0
                        Text("budget: \(tokens)/\(max)")
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundColor(.gray)
                            .lineLimit(1)
                    }
                }
            }
        }
        .padding(.vertical, 4)
        .listRowBackground(Color.clear)
    }
}

extension GraphEvent {
    /// Icon name for the event type (SF Symbols)
    var iconName: String {
        switch eventType {
        // Graph Structure
        case .nodeAdded: return "plus.circle.fill"
        case .nodeUpdated: return "pencil.circle.fill"
        case .nodeRemoved: return "minus.circle.fill"
        case .edgeAdded: return "link"
        case .edgeUpdated: return "link.badge.plus"

        // Scan Lifecycle
        case .scanStarted: return "play.circle.fill"
        case .scanPhaseChanged: return "arrow.triangle.2.circlepath.circle.fill"
        case .scanCompleted: return "checkmark.seal.fill"
        case .scanFailed: return "exclamationmark.triangle.fill"

        // Findings
        case .findingCreated: return "ant.fill"
        case .findingConfirmed: return "exclamationmark.shield.fill"
        case .findingDismissed: return "hand.thumbsup.fill"
        case .findingDiscovered: return "eye.fill"

        // Tool Execution
        case .toolStarted: return "hammer.fill"
        case .toolCompleted: return "hammer.circle.fill"

        // Logging & Reasoning
        case .log: return "text.alignleft"
        case .narrativeEmitted: return "bubble.left.and.bubble.right.fill"
        case .decisionMade: return "brain.head.profile"
        case .nexusInsightFormed: return "lightbulb.fill"
        case .actionNeeded: return "hand.raised.fill"

        // Security / Trinity
        case .circuitBreakerStateChanged: return "bolt.shield.fill"
        case .exploitValidated: return "lock.open.fill"
        case .exploitRejected: return "lock.fill"
        case .breachDetected: return "exclamationmark.octagon.fill"
        case .identityEstablished: return "person.fill.checkmark"

        // Diagnostic / Governance
        case .contractViolation: return "scroll.fill"
        case .orphanEventDropped: return "trash.fill"
        case .resourceGuardTrip: return "gauge.badge.minus"
        case .eventSilence: return "speaker.slash.fill"
        case .toolChurn: return "repeat.circle.fill"

        case .unknown: return "questionmark.circle"
        }
    }
}
