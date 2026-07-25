import Foundation
import Combine

// DEPRECATED: This client is no longer used.
// Replaced by EventStreamClient (SSE).
// Kept temporarily to satisfy Xcode project references.

public class LedgerStreamClient: ObservableObject {
    @Published public var events: [GraphEvent] = []
    @Published public var isConnected: Bool = false
    
    public init() {}
    public func connect() {}
    public func disconnect() {}
}
