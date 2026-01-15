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
