import SwiftUI

struct AuditFeedView: View {
    @StateObject private var client = LedgerStreamClient()

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Text("EPISTEMIC LEDGER API")
                    .font(.caption)
                    .fontWeight(.bold)
                    .foregroundColor(.gray)
                Spacer()
                Circle()
                    .fill(client.isConnected ? Color.green : Color.red)
                    .frame(width: 8, height: 8)
            }
            .padding()
            .background(Color.black.opacity(0.2))

            // List
            List(client.events) { event in
                EventRow(event: event)
            }
            .listStyle(.plain)
        }
        .background(Color(red: 0.05, green: 0.05, blue: 0.08))
    }
}

struct EventRow: View {
    let event: GraphEvent

    var color: Color {
        switch event.eventType {
        case .findingCreated, .findingConfirmed, .findingDiscovered: return .red
        case .scanFailed, .breachDetected: return .purple
        case .scanCompleted, .exploitValidated: return .green
        case .decisionMade, .narrativeEmitted: return .blue
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
        case .scanPhaseChanged:
            return event.payload["phase"]?.stringValue ?? ""
        case .decisionMade:
            return event.payload["intent"]?.stringValue ?? ""
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

                // Payload Dump (simplified for specific types)
                if event.eventType == .toolCompleted {
                    Text((event.payload["output"]?.stringValue ?? "").prefix(200))
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.gray)
                        .lineLimit(3)
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
