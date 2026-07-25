import SwiftUI

struct TierBadgeView: View {
    let tierShort: String
    let tierValue: Int?

    private var color: Color {
        switch tierValue {
        case 0: return .gray
        case 1: return .blue
        case 2: return .green
        case 3: return .orange
        case 4: return .red
        case 5: return .black
        default: return .secondary
        }
    }

    var body: some View {
        Text(tierShort)
            .font(.caption2)
            .fontWeight(.bold)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .foregroundColor(tierValue == 5 ? .white : color)
            .background(color.opacity(tierValue == 5 ? 0.9 : 0.15))
            .cornerRadius(6)
    }
}

