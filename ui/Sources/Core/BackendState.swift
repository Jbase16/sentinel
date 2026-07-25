//
// PURPOSE:
// This Swift component is part of the SentinelForge macOS UI.
// Defines the state machine for the Python backend connection.
//
// KEY RESPONSIBILITIES:
// - Track backend lifecycle states (stopped, starting, ready, failed)
// - Provide SwiftUI-compatible state representation
// - Enable proper error classification and user messaging
//
// INTEGRATION:
// - Used by: BackendManager, EventStreamClient, SentinelAPIClient
// - Depends on: Foundation
//

import Foundation

/// Represents the current state of the Python backend connection.
///
/// This enum provides a clear state machine for tracking the backend's
/// lifecycle, enabling proper error classification and user messaging.
/// Connection refused errors are treated as "starting" rather than failures.
public enum BackendState: Equatable, Hashable, Identifiable {
    case stopped
    case starting
    case ready
    case failed(Error)

    public var id: String {
        switch self {
        case .stopped:
            return "stopped"
        case .starting:
            return "starting"
        case .ready:
            return "ready"
        case .failed(let error):
            return "failed-\(error.localizedDescription.hashValue)"
        }
    }

    /// User-friendly description of the current state.
    public var description: String {
        switch self {
        case .stopped:
            return "Core Stopped"
        case .starting:
            return "Core Starting..."
        case .ready:
            return "Core Online"
        case .failed(let error):
            return "Core Failed: \(error.localizedDescription)"
        }
    }

    /// Equatable conformance: compares states, not error details for failed case.
    public static func == (lhs: BackendState, rhs: BackendState) -> Bool {
        switch (lhs, rhs) {
        case (.stopped, .stopped),
             (.starting, .starting),
             (.ready, .ready):
            return true
        case (.failed, .failed):
            return true
        default:
            return false
        }
    }

    /// Hashable conformance: hashes based on state type, not error details.
    public func hash(into hasher: inout Hasher) {
        switch self {
        case .stopped:
            hasher.combine(0)
        case .starting:
            hasher.combine(1)
        case .ready:
            hasher.combine(2)
        case .failed:
            hasher.combine(3)
        }
    }
}
