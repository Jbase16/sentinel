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
    let event: EpistemicEvent

    var color: Color {
        switch event.event_type {
        case "promoted": return .green
        case "suppressed": return .yellow
        case "conflict": return .red
        default: return .blue
        }
    }

    var title: String {
        switch event.event_type {
        case "observed":
            return (event.payload["tool"]?.stringValue ?? "Unknown Tool").uppercased()
        case "promoted":
            return (event.payload["title"]?.stringValue ?? "Finding").uppercased()
        default:
            return event.event_type.uppercased()
        }
    }

    var details: String {
        switch event.event_type {
        case "observed":
            return event.payload["target"]?.stringValue ?? ""
        case "promoted":
            return event.payload["severity"]?.stringValue ?? ""
        case "suppressed":
            return event.payload["reason_code"]?.stringValue ?? ""
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
                        Text("• " + details)
                            .font(.custom("Menlo", size: 12))
                            .foregroundColor(.gray)
                    }

                    Spacer()

                    Text(Date(timeIntervalSince1970: event.timestamp), style: .time)
                        .font(.caption2)
                        .foregroundColor(.gray)
                }

                // Payload Dump (simplified)
                if event.event_type == "observed" {
                    Text((event.payload["raw_output"]?.stringValue ?? "").prefix(200))
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
