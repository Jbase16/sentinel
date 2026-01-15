import SwiftUI

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
