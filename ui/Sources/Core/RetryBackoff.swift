//
// PURPOSE:
// This Swift component is part of the SentinelForge macOS UI.
// Provides exponential backoff retry logic with a specific schedule.
//
// KEY RESPONSIBILITIES:
// - Manages retry delays with a custom schedule to prevent log spam
// - Avoids hammering the socket while uvicorn is still binding
//
// INTEGRATION:
// - Used by: SentinelAPIClient, EventStreamClient, BackendManager
//

import Foundation

/// Manages retry delays with a custom backoff schedule.
///
/// Schedule:
/// - Attempt 1: immediately (0 ms)
/// - Attempt 2: +200 ms
/// - Attempt 3: +500 ms
/// - Attempt 4: +1 s
/// - Cap at ~5 s for subsequent attempts
public struct RetryBackoff: Sendable {

    /// Returns the delay in seconds for a given attempt number.
    ///
    /// - Parameter attempt: The attempt number (1-indexed)
    /// - Returns: The delay in seconds
    public static func delayForAttempt(_ attempt: Int) -> TimeInterval {
        switch attempt {
        case 1:
            return 0.0
        case 2:
            return 0.2
        case 3:
            return 0.5
        case 4:
            return 1.0
        default:
            return 5.0
        }
    }

    /// Performs an async sleep for the delay corresponding to the given attempt.
    ///
    /// - Parameter attempt: The attempt number (1-indexed)
    public static func sleep(for attempt: Int) async {
        let delay = delayForAttempt(attempt)
        if delay > 0 {
            try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
        }
    }
}
