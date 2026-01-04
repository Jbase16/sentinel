//
// PURPOSE:
// This Swift component is part of the SentinelForge macOS UI.
// [Specific purpose based on component name: HelixAppState]
//
// KEY RESPONSIBILITIES:
// - [Automatically generated - review and enhance based on actual functionality]
//
// INTEGRATION:
// - Used by: [To be documented]
// - Depends on: [To be documented]
//

import Combine
import Foundation
import SwiftUI

// Scan Mode (Strategos)
/// Enum ScanMode.
enum ScanMode: String, CaseIterable, Identifiable {
    case standard = "standard"
    case bugBounty = "bug_bounty"
    case stealth = "stealth"

    var id: String { rawValue }

    var displayName: String {
        // Switch over value.
        switch self {
        case .standard: return "Standard"
        case .bugBounty: return "Bug Bounty"
        case .stealth: return "Stealth"
        }
    }
}

// Holds shared UI + LLM state.
// ObservableObject means any @Published changes will re-render SwiftUI views.
@MainActor
/// Class HelixAppState.
public class HelixAppState: ObservableObject {

    @Published var thread: ChatThread
    @Published var isProcessing: Bool = false
    @Published var currentTab: SidebarTab = .dashboard

    // MARK: - Centralized State
    /// Scan running state
    @Published var isScanRunning: Bool = false

    /// Log items
    @Published var apiLogItems: [LogItem] = []

    // Services
    let eventClient = EventStreamClient()
    let apiClient: SentinelAPIClient
    let cortexStream: CortexStream
    let ptyClient: PTYClient

    private var cancellables = Set<AnyCancellable>()
    private var didSetupEventStreamSubscriptions = false
    private var seenEventIDs: Set<String> = []
    // Sequence tracking moved to AppStore
    // private var eventSequenceEpoch: Int = 1
    // private var lastEventSequence: Int = 0

    @Published var apiLogs: [String] = []  // Buffered logs from Python core
    @Published var apiResults: SentinelResults?  // Latest scan snapshot
    @Published var engineStatus: EngineStatus?
    @Published var aiStatus: AIStatus?
    @Published var availableModels: [String] = ModelRouter.defaultCandidates
    @Published var preferredModel: String = ModelRouter.defaultPreferredModel
    @Published var autoRoutingEnabled: Bool = true
    @Published var pendingActions: [PendingAction] = []
    @Published var isGhostActive: Bool = false
    @Published var ghostPort: Int? = nil

    // Report State (Persisted)
    @Published var reportContent: [String: String] = [:]
    @Published var reportIsGenerating: Bool = false
    @Published var selectedSection: String = "executive_summary"

    // Identity State (Doppelganger)
    @Published var currentIdentity: String? = nil
    @Published var currentRole: String? = nil

    // Security State
    @Published var activeBreachTarget: String? = nil

    private let llm: LLMService

    init(llm: LLMService) {
        self.llm = llm

        // Initialize Services
        self.apiClient = SentinelAPIClient()
        self.cortexStream = CortexStream()
        self.ptyClient = PTYClient()

        self.thread = ChatThread(title: "Main Chat", messages: [])
        self.availableModels = llm.availableModels
        self.preferredModel = llm.preferredModel
        self.autoRoutingEnabled = llm.autoRoutingEnabled

        // Wait for BackendManager to signal readiness
        NotificationCenter.default.addObserver(forName: .backendReady, object: nil, queue: .main) {
            [weak self] _ in
            Task { @MainActor in
                self?.connectServices()
            }
        }

        // Setup Combine bindings for LLM state
        setupLLMBindings()
    }

    private func connectServices() {
        print("[AppState] Backend Ready. Connecting Services...")
        if let wsURL = URL(string: "ws://127.0.0.1:8765/ws/graph") {
            cortexStream.connect(url: wsURL)
        }
        if let ptyURL = URL(string: "ws://127.0.0.1:8765/ws/pty") {
            ptyClient.connect(url: ptyURL)
        }

        self.refreshStatus()
        self.refreshGraph()  // Force initial graph load

        if !didSetupEventStreamSubscriptions {
            didSetupEventStreamSubscriptions = true

            // Subscribe BEFORE connecting so we don't drop early replay events.
            eventClient.eventPublisher
                .receive(on: RunLoop.main)
                .sink { [weak self] event in
                    guard let self else { return }

                    // Deduplicate by immutable event UUID (survives backend restarts/replays).
                    if self.seenEventIDs.contains(event.id) {
                        return
                    }
                    self.seenEventIDs.insert(event.id)
                    if self.seenEventIDs.count > 50_000 {
                        self.seenEventIDs.removeAll(keepingCapacity: true)
                    }

                    // Update scan-running state from the authoritative scan lifecycle events.
                    switch event.eventType {
                    case .scanStarted:
                        self.isScanRunning = true
                        let target = event.payload["target"]?.stringValue ?? "unknown"
                        let toolCount = (event.payload["modules"]?.value as? [Any])?.count ?? 0
                        self.apiLogItems.append(
                            LogItem(
                                id: UUID(), text: "[Scan] started: \(target) (\(toolCount) tools)"))
                        self.refreshGraph()
                    case .scanCompleted:
                        self.isScanRunning = false
                        self.refreshResults()
                        self.refreshGraph()
                    case .scanFailed:
                        self.isScanRunning = false
                        self.refreshResults()
                    case .scanPhaseChanged:
                        if let phase = event.payload["phase"]?.stringValue {
                            let text = "🔄 [Phase] Transitioned to \(phase)"
                            self.apiLogs.append(text)
                            self.apiLogItems.append(LogItem(id: UUID(), text: text))
                        }
                    case .decisionMade:
                        if let intent = event.payload["intent"]?.stringValue,
                            let reason = event.payload["reason"]?.stringValue
                        {
                            let text = "🧠 [Decision] \(intent) → \(reason)"
                            self.apiLogs.append(text)
                            self.apiLogItems.append(LogItem(id: UUID(), text: text))
                        }
                    case .actionNeeded:
                        if let action = self.decodeAction(from: event.payload) {
                            if !self.pendingActions.contains(where: { $0.id == action.id }) {
                                self.pendingActions.append(action)
                            }
                        }
                    case .findingCreated, .findingConfirmed, .findingDismissed, .toolCompleted:
                        self.refreshResults()
                        self.refreshGraph()

                    // Doppelganger
                    case .identityEstablished:
                        if let persona = event.payload["persona_id"]?.stringValue {
                            self.currentIdentity = persona
                            self.currentRole = event.payload["role"]?.stringValue
                            self.apiLogs.append("🎭 [Doppelganger] Identity Active: \(persona)")
                        }

                    // Crash Reflex / Breach
                    case .breachDetected:
                        let target = event.payload["target_node_id"]?.stringValue ?? "unknown"
                        let type = event.payload["type"]?.stringValue ?? "BREACH"
                        let sev = event.payload["severity"]?.doubleValue ?? 0.0
                        let msg = "🚨 [ORACLE] \(type) DETECTED at \(target) (Severity: \(sev))"

                        self.activeBreachTarget = target
                        self.apiLogs.append(msg)
                        self.apiLogItems.append(LogItem(id: UUID(), text: msg))
                        self.refreshResults()  // Refresh graph to show red node
                        self.refreshGraph()

                        // Auto-clear breach alert after 5 seconds
                        DispatchQueue.main.asyncAfter(deadline: .now() + 5) {
                            if self.activeBreachTarget == target {
                                self.activeBreachTarget = nil
                            }
                        }

                    default:
                        break
                    }

                    // Render selected events into the Live Logs console.
                    let rendered = self.renderLiveLogLine(event: event)
                    guard let rendered else { return }

                    self.apiLogItems.append(LogItem(id: UUID(), text: rendered))
                }
                .store(in: &cancellables)
        }

        // Connect unified event stream (provides sequence IDs)
        eventClient.connect()
    }

    // ... (renderLiveLogLine implementation omitted for brevity as it is unchanged) ...

    /// Pull the latest Pressure Graph snapshot.
    func refreshGraph() {
        Task {
            do {
                if let graph = try await apiClient.fetchGraph() {
                    print(
                        "[AppState] Graph refreshed: \(graph.count.nodes) nodes, \(graph.count.edges) edges"
                    )
                    cortexStream.updateFromPressureGraph(graph)
                } else {
                    print("[AppState] Graph refresh returned nil (204 No Content)")
                }
            } catch {
                print("[AppState] Failed to refresh graph: \(error)")
            }
        }
    }

    /// Ask Python core to cancel any active scan.
    func cancelScan() {
        Task {
            try? await apiClient.cancelScan()
            await MainActor.run {
                self.isScanRunning = false
            }
            self.refreshStatus()
        }
    }

    private func decodeAction(from payload: [String: AnyCodable]) -> PendingAction? {
        guard let id = payload["id"]?.stringValue,
            let tool = payload["tool"]?.stringValue,
            let args = payload["args"]?.value as? [String]
        else { return nil }

        return PendingAction(
            id: id,
            tool: tool,
            args: args,
            reason: payload["reason"]?.stringValue,
            target: payload["target"]?.stringValue,
            timestamp: payload["timestamp"]?.stringValue
        )
    }

    @MainActor
    private func mergePolledLogs(_ lines: [String]) {
        // Guard condition.
        guard !lines.isEmpty else { return }

        // `/logs` returns a tail window; merge by finding the last seen line.
        let lastText = apiLogs.last
        let startIndex: Int
        // Conditional branch.
        if let lastText, let idx = lines.lastIndex(of: lastText) {
            startIndex = idx + 1
        } else {
            startIndex = 0
        }

        let newLines = startIndex < lines.count ? Array(lines[startIndex...]) : []
        // Guard condition.
        guard !newLines.isEmpty else { return }

        apiLogs.append(contentsOf: newLines)

        // Conditional branch.
        if !eventClient.isConnected {
            // Loop over items.
            for line in newLines {
                // let nextID = (apiLogItems.last?.id ?? 0) + 1
                apiLogItems.append(LogItem(id: UUID(), text: line))
            }
        }
    }

    /// Function approveAction.
    func approveAction(_ action: PendingAction) {
        Task {
            try? await apiClient.approveAction(id: action.id)
            await MainActor.run {
                self.pendingActions.removeAll { $0.id == action.id }
            }
        }
    }

    /// Function denyAction.
    func denyAction(_ action: PendingAction) {
        Task {
            try? await apiClient.denyAction(id: action.id)
            await MainActor.run {
                self.pendingActions.removeAll { $0.id == action.id }
            }
        }
    }

    /// Function setupLLMBindings.
    func setupLLMBindings() {
        llm.textStream
            .receive(on: RunLoop.main)
            .assign(to: \.thread.streamBuffer, on: self)
            .store(in: &cancellables)

        llm.isProcessing
            .receive(on: RunLoop.main)
            .assign(to: \.isProcessing, on: self)
            .store(in: &cancellables)

        llm.threadPublisher
            .receive(on: RunLoop.main)
            .assign(to: \.thread, on: self)
            .store(in: &cancellables)
    }

    /// Refresh backend connection status.
    func refreshStatus() {
        Task {
            do {
                let status = try await apiClient.fetchStatus()
                await MainActor.run {
                    self.engineStatus = status.ai
                    // self.aiStatus = status.ai // Wait, type mismatch? Using engineStatus.ai for now
                }
            } catch {
                print("[AppState] Status refresh failed: \(error)")
            }
        }
    }

    /// Refresh scan findings/results.
    func refreshResults() {
        Task {
            do {
                if let results = try await apiClient.fetchResults() {
                    await MainActor.run {
                        self.apiResults = results
                    }
                }
            } catch {
                print("[AppState] Results refresh failed: \(error)")
            }
        }
    }

    /// Function toggleGhost.
    func toggleGhost() {
        Task {
            // Conditional branch.
            if isGhostActive {
                _ = try? await apiClient.stopGhost()
                await MainActor.run {
                    self.isGhostActive = false
                    self.ghostPort = nil
                }
            } else {
                // Do-catch block.
                do {
                    let port = try await apiClient.startGhost(port: 8080)
                    await MainActor.run {
                        self.isGhostActive = true
                        self.ghostPort = port
                    }
                } catch {
                    print("[AppState] Failed to start Ghost Protocol: \(error)")
                }
            }
        }
    }
}

/// Struct PendingAction.
struct PendingAction: Identifiable, Decodable {
    let id: String
    let tool: String
    let args: [String]
    let reason: String?
    let target: String?
    let timestamp: String?
}
