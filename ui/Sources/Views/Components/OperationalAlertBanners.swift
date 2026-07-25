import SwiftUI

struct P0AlertBanner: View {
    let alert: P0Alert
    let onDismiss: () -> Void

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "exclamationmark.octagon.fill")
                .foregroundColor(.white)
            VStack(alignment: .leading, spacing: 2) {
                Text("P0 Source/Config Exposure")
                    .font(.caption)
                    .fontWeight(.bold)
                    .foregroundColor(.white.opacity(0.95))
                Text(alert.summary)
                    .font(.subheadline)
                    .foregroundColor(.white)
                    .lineLimit(2)
                Text(alert.target)
                    .font(.caption2)
                    .foregroundColor(.white.opacity(0.9))
                    .lineLimit(1)
            }
            Spacer()
            Button(action: onDismiss) {
                Image(systemName: "xmark.circle.fill")
                    .foregroundColor(.white.opacity(0.9))
            }
            .buttonStyle(.plain)
        }
        .padding(.vertical, 10)
        .padding(.horizontal, 12)
        .background(Color.red.opacity(0.85))
        .cornerRadius(10)
        .shadow(color: Color.black.opacity(0.15), radius: 3, x: 0, y: 2)
        .padding(.horizontal)
        .padding(.top, 6)
    }
}

struct WAFStatusBanner: View {
    let waf: WAFStatus
    let onDismiss: () -> Void

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "shield.lefthalf.filled")
                .foregroundColor(.white)
            VStack(alignment: .leading, spacing: 2) {
                Text("WAF Detected")
                    .font(.caption)
                    .fontWeight(.bold)
                    .foregroundColor(.white.opacity(0.95))
                Text(waf.wafName)
                    .font(.subheadline)
                    .foregroundColor(.white)
                    .lineLimit(1)
            }
            Spacer()
            Button(action: onDismiss) {
                Image(systemName: "xmark.circle.fill")
                    .foregroundColor(.white.opacity(0.9))
            }
            .buttonStyle(.plain)
        }
        .padding(.vertical, 10)
        .padding(.horizontal, 12)
        .background(Color.orange.opacity(0.75))
        .cornerRadius(10)
        .shadow(color: Color.black.opacity(0.12), radius: 3, x: 0, y: 2)
        .padding(.horizontal)
        .padding(.top, 6)
    }
}

