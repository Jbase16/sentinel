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
    let cortexClient: CortexClient

    private var cancellables = Set<AnyCancellable>()
    private var didSetupEventStreamSubscriptions = false
    private var seenEventIDs: Set<String> = []

    // MARK: - Analysis State (Phase 11)
    @Published var graphAnalysis: TopologyResponse? = nil
    @Published var insightsByNode: [String: [InsightClaim]] = [:]

    // MARK: - Replay State (Time Travel)
    @Published var allEvents: [GraphEvent] = []  // The Tape
    @Published var replayCursor: Int? = nil  // nil = Live, Int = Replay Index
    @Published var isReplaying: Bool = false
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

    // MARK: - Phase 12: Reporting State
    @Published var activeReportMarkdown: String = ""
    @Published var activeReportMeta: ReportGenerateResponse? = nil
    @Published var activePoCByFindingId: [String: PoCResponse] = [:]

    private let llm: LLMService

    init(llm: LLMService) {
        self.llm = llm

        // Initialize Services
        self.apiClient = SentinelAPIClient()
        self.cortexStream = CortexStream()
        self.ptyClient = PTYClient()
        self.cortexClient = CortexClient()

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
                        // Backend sends "allowed_tools" not "modules"
                        let toolCount =
                            (event.payload["allowed_tools"]?.value as? [Any])?.count ?? 0
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
                        if let error = event.payload["error"]?.stringValue {
                            let code = event.payload["error_code"]?.stringValue
                            let details = event.payload["error_details"]?.value as? [String: Any]
                            let detailText = details?.description ?? ""
                            let prefix = code != nil ? "(\(code!)) " : ""
                            let text = "🛑 [Scan] Failed: \(prefix)\(error) \(detailText)"
                            self.apiLogs.append(text)
                            self.apiLogItems.append(LogItem(id: UUID(), text: text))
                        }
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
                    case .findingCreated, .findingConfirmed, .findingDismissed:
                        self.refreshResults()
                        self.refreshGraph()
                    case .toolCompleted:
                        if let error = event.payload["error"]?.value as? [String: Any],
                            let tool = error["tool"] as? String
                        {
                            let exitCode =
                                (error["exit_code"] as? Int)
                                ?? (error["exit_code"] as? NSNumber)?.intValue
                                ?? -1
                            let stderr = error["stderr"] as? String ?? "Unknown error"
                            let text = "⚠️ [Tool] \(tool) failed (exit \(exitCode)): \(stderr)"
                            self.apiLogs.append(text)
                            self.apiLogItems.append(LogItem(id: UUID(), text: text))
                        }
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

            eventClient.graphEventPublisher
                .receive(on: RunLoop.main)
                .sink { [weak self] event in
                    guard let self else { return }
                    guard !self.isReplaying else { return }

                    self.cortexStream.processEvent(event)
                }
                .store(in: &cancellables)

            // Replay Buffer Subscription
            // Capture ALL events for time travel
            eventClient.eventPublisher
                .receive(on: RunLoop.main)
                .sink { [weak self] event in
                    self?.allEvents.append(event)

                    // If we are LIVE, processed events flow normally.
                    // If we are REPLAYING, we capture them but do NOT process them into the view
                    // until the user returns to live mode (or scrubs forward).
                }
                .store(in: &cancellables)
        }

        // Connect unified event stream (provides sequence IDs)
        eventClient.connect()

        eventClient.$isConnected
            .dropFirst()
            .receive(on: RunLoop.main)
            .sink { [weak self] connected in
                guard let self else { return }
                guard !connected, self.isScanRunning else { return }
                Task { @MainActor in
                    try? await Task.sleep(nanoseconds: 2_000_000_000)
                    self.eventClient.reconnectNow()
                }
            }
            .store(in: &cancellables)
    }

    private func renderLiveLogLine(event: GraphEvent) -> String? {
        if event.eventType == .log {
            return event.payload["line"]?.stringValue ?? event.payload["message"]?.stringValue
        }
        return nil
    }

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
                    self.engineStatus = status
                    self.aiStatus = status?.ai
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
                        // Defensive merge: Don't overwrite existing findings with empty/incomplete data
                        // during an active scan. This prevents findings from disappearing when the
                        // backend returns a partial snapshot.
                        let currentFindingsCount = self.apiResults?.findings?.count ?? 0
                        let newFindingsCount = results.findings?.count ?? 0

                        // Only update if:
                        // 1. We have no current results yet, OR
                        // 2. New results have >= findings count (never go backwards), OR
                        // 3. Scan is not running (allow full replacement when scan is complete)
                        if self.apiResults == nil
                            || newFindingsCount >= currentFindingsCount
                            || !self.isScanRunning {
                            self.apiResults = results
                        } else {
                            print(
                                "[AppState] Ignoring partial results refresh: current=\(currentFindingsCount), new=\(newFindingsCount)"
                            )
                        }
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

    /// Send a message to the AI.
    func send(_ text: String) {
        let userMsg = ChatMessage(role: .user, text: text)
        thread.append(userMsg)

        // Placeholder for assistant response
        let assistantMsg = ChatMessage(role: .assistant, text: "")
        thread.append(assistantMsg)

        llm.generate(prompt: text) { [weak self] token in
            guard let self else { return }
            // Update the last message directly
            if var last = self.thread.messages.last, last.role == .assistant {
                last.text += token
                self.thread.messages[self.thread.messages.count - 1] = last
            }
        }
    }

    /// Function startScan.
    func startScan(target: String, modules: [String], mode: ScanMode) {
        print("[AppState] startScan invoked target=\(target) mode=\(mode.rawValue)")
        Task {
            do {
                print("[AppState] About to call apiClient.startScan...")
                try await apiClient.startScan(
                    target: target, modules: modules, mode: mode.rawValue)
                print("[AppState] apiClient.startScan succeeded")
            } catch {
                print("[AppState] Failed to start scan")
                print("  error type: \(type(of: error))")
                print("  error: \(error)")

                if let urlError = error as? URLError {
                    print("  urlError.code: \(urlError.code)")
                    print(" URLError description: \(urlError.localizedDescription)")
                }

            }
        }
    }

    /// Function clearLogs.
    func clearLogs() {
        apiLogs.removeAll()
        apiLogItems.removeAll()
    }

    // MARK: - Time Travel / Replay Logic

    func enterReplayMode() {
        guard !isReplaying else { return }
        isReplaying = true
        replayCursor = allEvents.count - 1

        print("[TimeTravel] Entered Replay Mode. Cursor: \(replayCursor ?? 0)")
    }

    func exitReplayMode() {
        guard isReplaying else { return }
        isReplaying = false
        replayCursor = nil

        // Force refresh to sync with backend state
        refreshGraph()

        print("[TimeTravel] Exited Replay Mode. Resuming Live Stream.")
    }

    /// Seek to a specific index in the event tape.
    /// This rebuilds the entire application state (Graph + Logs) from the filtered stream.
    func seek(to index: Int) {
        let safeIndex = max(0, min(index, allEvents.count - 1))
        replayCursor = safeIndex

        // 1. Reset State
        cortexStream.reset()
        apiLogs.removeAll()
        apiLogItems.removeAll()
        isScanRunning = false
        activeBreachTarget = nil
        pendingActions.removeAll()
        // Note: We don't reset `allEvents`, that's our source of truth!

        // 2. Re-apply events up to cursor
        let eventsToReplay = Array(allEvents.prefix(through: safeIndex))
        print("[TimeTravel] Replaying \(eventsToReplay.count) events (Target: \(safeIndex))...")

        // Batch Graph Update (Performance critical)
        cortexStream.processBatch(eventsToReplay)

        // Batch Log/Lifecycle Update
        var newLogs: [LogItem] = []

        for event in eventsToReplay {
            // 1. Logs
            if let rendered = renderLiveLogLine(event: event) {
                newLogs.append(LogItem(id: UUID(), text: rendered))
            }
            // 2. Lifecycle
            processLifecycleEvent(event)
        }

        self.apiLogItems = newLogs

        // 3. Force UI Refresh
        // (Published properties update automatically)
    }

    private func processLifecycleEvent(_ event: GraphEvent) {
        switch event.eventType {
        case .scanStarted:
            isScanRunning = true
        case .scanCompleted, .scanFailed:
            isScanRunning = false
        case .breachDetected:
            let target = event.payload["target_node_id"]?.stringValue ?? "unknown"
            self.activeBreachTarget = target
            DispatchQueue.main.asyncAfter(deadline: .now() + 5) {
                if self.activeBreachTarget == target {
                    self.activeBreachTarget = nil
                }
            }
        default: break
        }
    }

    // Legacy single-event processor (can be removed if unused, or kept for fine-grained steps)
    private func processEvent(_ event: GraphEvent) {
        if let rendered = renderLiveLogLine(event: event) {
            apiLogItems.append(LogItem(id: UUID(), text: rendered))
        }
        cortexStream.processEvent(event)
        processLifecycleEvent(event)
    }

    // MARK: - Semantic Analysis (Phase 11)

    func fetchAnalysis() {
        Task {
            // Snapshot current graph state
            let nodes = cortexStream.nodes
            let edges = cortexStream.edges

            // Map to DTOs
            let nodeDTOs = nodes.map { node in
                NodeDTO(
                    id: node.id,
                    type: node.type,
                    attributes: [
                        "severity": node.severity ?? "",
                        "pressure": String(node.pressure ?? 0),
                    ]
                )
            }

            let edgeDTOs = edges.map { edge in
                EdgeDTO(
                    source: edge.source,
                    target: edge.target,
                    type: edge.type ?? "unknown",
                    weight: 1.0
                )
            }

            let graphDTO = GraphDataDTO(nodes: nodeDTOs, edges: edgeDTOs)

            // Determine entry/critical nodes?
            // Heuristic placeholder until Strategos exposes authoritative entry/asset classification.
            // Backend GraphAnalyzer requires entry_nodes to find paths.
            // Let's use nodes with type="entry" or hardcoded "INTERNET" if it exists.

            let entryNodes = nodes.filter { $0.type == "entry" || $0.id == "INTERNET" }.map {
                $0.id
            }
            let criticalNodes = nodes.filter { ($0.pressure ?? 0) > 0.8 }.map { $0.id }  // High pressure nodes

            do {
                let analysis = try await cortexClient.fetchTopology(
                    graph: graphDTO,
                    entryNodes: entryNodes,
                    criticalAssets: criticalNodes
                )

                await MainActor.run {
                    self.graphAnalysis = analysis
                    print(
                        "[Analysis] Received topology: \(analysis.critical_paths?.count ?? 0) paths"
                    )
                }
            } catch {
                print("[Analysis] Topology fetch failed: \(error)")
            }
        }
    }

    func fetchInsights(for nodeID: String) {
        guard let analysis = graphAnalysis else {
            print("[Analysis] Skipping insight fetch - No underlying topology analysis available.")
            return
        }

        Task {
            // Snapshot current graph state (Similar to above, could refactor into helper)
            let nodes = cortexStream.nodes
            let edges = cortexStream.edges

            let nodeDTOs = nodes.map { node in
                NodeDTO(
                    id: node.id,
                    type: node.type,
                    attributes: [
                        "severity": node.severity ?? "",
                        "pressure": String(node.pressure ?? 0),
                    ]
                )
            }
            let edgeDTOs = edges.map { edge in
                EdgeDTO(
                    source: edge.source, target: edge.target, type: edge.type ?? "unknown",
                    weight: 1.0)
            }
            let graphDTO = GraphDataDTO(nodes: nodeDTOs, edges: edgeDTOs)

            // Use the authoritative hash from the topology analysis
            let hash = analysis.graph_hash

            do {
                // TODO: Selection context should drive insight type (e.g. critical_path vs cluster_summary)
                let response = try await cortexClient.fetchInsights(
                    graph: graphDTO,
                    hash: hash,
                    nodes: [nodeID],
                    type: "cluster_summary"  // Default type
                )

                await MainActor.run {
                    self.insightsByNode[nodeID] = response.insights
                    print("[Analysis] Received \(response.insights.count) insights for \(nodeID)")
                }
            } catch {
                print("[Analysis] Insights fetch failed: \(error)")
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

struct ReportGenerateResponse: Decodable {
    let report_id: String
    let created_at: String
    let target: String
    let scope: String?
    let format: String
    let content: String
}

struct PoCResponse: Decodable {
    let finding_id: String
    let title: String
    let risk: String
    let safe: Bool
    let commands: [String]
    let notes: [String]
    let created_at: String
}

extension HelixAppState {
    // MARK: - Reporting & Proof of Concept (Phase 12)

    func generateReport(target: String, scope: String? = nil, format: String = "markdown") async {
        do {
            let decoded = try await apiClient.generateReport(
                target: target,
                scope: scope,
                format: format,
                includeAttackPaths: true,
                maxPaths: 5
            )
            await MainActor.run {
                self.activeReportMeta = decoded
                self.activeReportMarkdown =
                    (decoded.format.lowercased() == "markdown") ? decoded.content : decoded.content
            }
        } catch {
            print("[Report] Generation failed: \(error)")
            await MainActor.run {
                self.activeReportMeta = nil
                self.activeReportMarkdown =
                    "Report generation failed: \(error.localizedDescription)"
            }
        }
    }

    func fetchPoC(findingId: String) async {
        do {
            let decoded = try await apiClient.fetchPoC(findingId: findingId)
            await MainActor.run {
                self.activePoCByFindingId[findingId] = decoded
            }
        } catch {
            print("[PoC] Fetch failed: \(error)")
            await MainActor.run {
                self.activePoCByFindingId[findingId] = PoCResponse(
                    finding_id: findingId,
                    title: "PoC unavailable",
                    risk: "unknown",
                    safe: false,
                    commands: [],
                    notes: ["Failed to fetch PoC: \(error.localizedDescription)"],
                    created_at: ""
                )
            }
        }
    }
}

// MARK: - TEMPORARY CONSOLIDATION: CortexClient
// Moved here because Xcode project target membership for 'Services/CortexClient.swift' is likely broken.

public struct AnalysisCaps: Codable {
    public var max_paths: Int = 5
    public var timeout_seconds: Double = 5.0
    public var approximation_threshold: Int = 500

    public init() {}
}

public struct TopologyRequest: Codable {
    public let graph_data: GraphDataDTO
    public let entry_nodes: [String]
    public let critical_assets: [String]
    public let caps: AnalysisCaps
}

public struct PathResult: Codable {
    public let path: [String]
    public let score: [Double]  // (length, risk, bottleneck)
    public let metadata: [String: String]?
}

public struct TopologyResponse: Codable {
    public let graph_hash: String
    public let computed_at: Double
    public let centrality: [String: Double]
    public let communities: [String: Int]
    public let critical_paths: [PathResult]?
    public let limits_applied: [String: Bool]
}

public struct InsightRequest: Codable {
    public let graph_hash: String
    public let target_nodes: [String]
    public let insight_type: String
    public let graph_data: GraphDataDTO
}

public struct InsightClaim: Codable, Identifiable {
    public var id: String { claim + String(confidence) }
    public let claim: String
    public let evidence: [String]
    public let confidence: Double
}

public struct InsightResponse: Codable {
    public let graph_hash: String
    public let insights: [InsightClaim]
}

public struct GraphDataDTO: Codable {
    public let nodes: [NodeDTO]
    public let edges: [EdgeDTO]
}

public struct NodeDTO: Codable {
    public let id: String
    public let type: String
    public let attributes: [String: String]
}

public struct EdgeDTO: Codable {
    public let source: String
    public let target: String
    public let type: String
    public let weight: Double
}

public actor CortexClient {
    private let baseURL = URL(string: "http://127.0.0.1:8765/v1/cortex")!

    public init() {}

    private func getToken() -> String? {
        let path = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".sentinelforge/api_token")
        return try? String(contentsOf: path, encoding: .utf8).trimmingCharacters(
            in: .whitespacesAndNewlines)
    }

    public func fetchTopology(graph: GraphDataDTO, entryNodes: [String], criticalAssets: [String])
        async throws -> TopologyResponse
    {
        let caps = AnalysisCaps()
        let requestPayload = TopologyRequest(
            graph_data: graph,
            entry_nodes: entryNodes,
            critical_assets: criticalAssets,
            caps: caps
        )

        return try await performRequest(endpoint: "analysis/topology", payload: requestPayload)
    }

    public func fetchInsights(graph: GraphDataDTO, hash: String, nodes: [String], type: String)
        async throws -> InsightResponse
    {
        let requestPayload = InsightRequest(
            graph_hash: hash,
            target_nodes: nodes,
            insight_type: type,
            graph_data: graph
        )

        return try await performRequest(endpoint: "analysis/insights", payload: requestPayload)
    }

    private func performRequest<T: Codable, R: Codable>(endpoint: String, payload: T) async throws
        -> R
    {
        let url = baseURL.appendingPathComponent(endpoint)
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        if let token = getToken() {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        request.httpBody = try JSONEncoder().encode(payload)

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse,
            (200...299).contains(httpResponse.statusCode)
        else {
            throw URLError(.badServerResponse)
        }

        return try JSONDecoder().decode(R.self, from: data)
    }
}
