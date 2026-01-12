//
// PURPOSE:
// This Swift component is part of the SentinelForge macOS UI.
// Provides error classification logic for backend connection errors.
//
// KEY RESPONSIBILITIES:
// - Classify connection errors (connection refused vs. real failures)
// - Determine which errors should be logged
// - Determine which errors should be shown to users
//
// INTEGRATION:
// - Used by: BackendManager, EventStreamClient, SentinelAPIClient
// - Depends on: Foundation
//

import Foundation

/// Error classifier for backend connection errors.
///
/// This class provides static methods to classify errors and determine
/// appropriate handling strategies. Connection refused errors are treated
/// as "backend is starting" rather than actual failures.
public enum ErrorClassifier {

    /// Key for the CFStream error code in NSError userInfo dictionary.
    private static let kCFStreamErrorCodeKey = "_kCFStreamErrorCodeKey"

    /// Checks if the error is a connection refused error.
    ///
    /// Connection refused (NSURLErrorDomain code -1004 with CFStream error code 61)
    /// indicates the backend is starting up, not a real failure.
    ///
    /// - Parameter error: The error to check
    /// - Returns: true if the error is a connection refused error
    public static func isConnectionRefused(_ error: Error) -> Bool {
        let nsError = error as NSError

        // Check for NSURLErrorDomain with code -1004 (connection refused)
        guard nsError.domain == NSURLErrorDomain,
              nsError.code == NSURLErrorCannotConnectToHost
        else {
            return false
        }

        // Check for CFStream error code 61 (connection refused)
        if let streamErrorCode = nsError.userInfo[kCFStreamErrorCodeKey] as? Int {
            return streamErrorCode == 61
        }

        return false
    }

    /// Determines if an error should be logged as an error.
    ///
    /// Connection refused errors are not logged as errors since they indicate
    /// the backend is starting up. Only real failures should be logged.
    ///
    /// - Parameter error: The error to check
    /// - Returns: true if the error should be logged as an error
    public static func shouldLogAsError(_ error: Error) -> Bool {
        // Don't log connection refused as error - it's expected during startup
        if isConnectionRefused(error) {
            return false
        }

        let nsError = error as NSError

        // Log timeouts
        if nsError.domain == NSURLErrorDomain {
            switch nsError.code {
            case NSURLErrorTimedOut,
                 NSURLErrorCannotFindHost,
                 NSURLErrorCannotConnectToHost,
                 NSURLErrorNetworkConnectionLost,
                 NSURLErrorDNSLookupFailed:
                return true
            default:
                break
            }
        }

        // Log HTTP errors - check for HTTPURLResponse in userInfo
        if nsError.domain == NSURLErrorDomain {
            // Try to extract HTTPURLResponse from userInfo
            for value in nsError.userInfo.values {
                if let httpResponse = value as? HTTPURLResponse {
                    switch httpResponse.statusCode {
                    case 400...499:  // Client errors (auth failures, bad requests)
                        return true
                    case 500...599:  // Server errors
                        return true
                    default:
                        break
                    }
                    break
                }
            }
        }

        // Log JSON decoding errors
        if error is DecodingError {
            return true
        }

        // Log any otherNSError that isn't connection refused
        return true
    }

    /// Determines if an error should be shown to the user.
    ///
    /// Connection refused errors should not be shown to users during startup.
    ///
    /// - Parameter error: The error to check
    /// - Returns: true if the error should be shown to the user
    public static func shouldShowToUser(_ error: Error) -> Bool {
        // Don't show connection refused to users - it's expected during startup
        return !isConnectionRefused(error)
    }

    /// Gets a user-friendly description for an error.
    ///
    /// - Parameter error: The error to describe
    /// - Returns: A user-friendly description string
    public static func userDescription(for error: Error) -> String {
        if isConnectionRefused(error) {
            return "Backend is starting..."
        }

        let nsError = error as NSError

        if nsError.domain == NSURLErrorDomain {
            switch nsError.code {
            case NSURLErrorTimedOut:
                return "Request timed out"
            case NSURLErrorCannotFindHost:
                return "Backend not found"
            case NSURLErrorNetworkConnectionLost:
                return "Connection lost"
            case NSURLErrorDNSLookupFailed:
                return "DNS lookup failed"
            default:
                break
            }
        }

        if error is DecodingError {
            return "Invalid response from backend"
        }

        return error.localizedDescription
    }
}
