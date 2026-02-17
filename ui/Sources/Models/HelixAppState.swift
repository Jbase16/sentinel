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

    /// Scan start time (for timer display)
    @Published var scanStartTime: Date? = nil

    /// Log items
    @Published var apiLogItems: [LogItem] = []

    /// Decisions
    @Published var decisions: [Decision] = []

    // MARK: - Operational State (UI transparency)
    @Published var toolMetadata: [String: ToolMetadata] = [:]
    @Published var toolModeInfo: [String: ModeTierInfo] = [:]
    @Published var capabilityGateSnapshot: CapabilityGateSnapshot? = nil
    @Published var activeP0Alert: P0Alert? = nil
    @Published var wafStatus: WAFStatus? = nil

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
    @Published var latestPressureGraph: PressureGraphDTO? = nil
    @Published var showDecisionLayerInGraph: Bool = false
    @Published var hideLowSignalGraphNodes: Bool = true

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
        self.refreshToolMetadata()
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
                    self.allEvents.append(event)

                    // Update scan-running state from the authoritative scan lifecycle events.
                    switch event.eventType {
                    case .scanStarted:
                        self.decisions.removeAll()  // Clear old decisions
                        self.isScanRunning = true
                        self.scanStartTime = Date(timeIntervalSince1970: event.timestamp)
                        self.capabilityGateSnapshot = nil
                        self.activeP0Alert = nil
                        self.wafStatus = nil
                        let target = event.payload["target"]?.stringValue ?? "unknown"
                        // Backend sends "allowed_tools" not "modules"
                        let toolCount =
                            (event.payload["allowed_tools"]?.value as? [Any])?.count ?? 0
                        self.apiLogItems.append(
                            LogItem(
                                id: UUID(), text: "[Scan] started: \(target) (\(toolCount) tools)"))
                        // Delay graph refresh to allow session initialization to complete
                        // Prevents "badStatus" error when graph endpoint is called before session is ready
                        Task {
                            try? await Task.sleep(nanoseconds: 500_000_000)  // 500ms delay
                            await MainActor.run {
                                self.refreshGraph()
                            }
                        }
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
                        // Extract rich decision data
                        let payload = event.payload
                        let id = payload["decision_id"]?.stringValue ?? UUID().uuidString
                        let type = payload["decision_type"]?.stringValue ?? "unknown"
                        let action = payload["selected_action"]?.stringValue ?? "unknown"
                        let reason = payload["rationale"]?.stringValue ?? "No rationale provided"
                        let conf = payload["confidence"]?.doubleValue ?? 1.0

                        // Lists need safer casting from AnyCodable array
                        let alts = (payload["alternatives_considered"]?.value as? [Any])?.map {
                            "\($0)"
                        }
                        let supp = (payload["suppressed_actions"]?.value as? [Any])?.map { "\($0)" }
                        let triggers = (payload["triggers"]?.value as? [Any])?.map { "\($0)" }

                        // Sequence might be mixed type
                        let seq =
                            payload["scope"]?.dictValue?["_sequence"] as? Int
                            ?? (payload["scope"]?.dictValue?["_sequence"] as? Double).map {
                                Int($0)
                            }

                        // Evidence
                        let evidence = payload["evidence"]?.dictValue?.reduce(
                            into: [String: AnyCodable]()
                        ) {
                            $0[$1.key] = AnyCodable($1.value)
                        }

                        let decision = Decision(
                            id: id,
                            scanId: payload["scan_id"]?.stringValue,
                            type: type,
                            selectedAction: action,
                            rationale: reason,
                            confidence: conf,
                            alternatives: alts,
                            suppressed: supp,
                            sequence: seq,
                            triggers: triggers,
                            timestamp: Date(timeIntervalSince1970: event.timestamp),
                            evidence: evidence
                        )

                        self.decisions.append(decision)

                        // Enforce Monotonic Ordering: Sort by (Sequence || Int.max), then Timestamp
                        self.decisions.sort {
                            let seq1 = $0.sequence ?? Int.max
                            let seq2 = $1.sequence ?? Int.max
                            if seq1 != seq2 { return seq1 < seq2 }
                            return $0.timestamp < $1.timestamp
                        }

                        let text = "🧠 [Decision] \(type) → \(action)"
                        self.apiLogs.append(text)
                        self.apiLogItems.append(LogItem(id: UUID(), text: text))

                        // Update operational UI state from select evidence keys.
                        self.applyOperationalStateFromDecision(type: type, evidence: evidence ?? [:])
                    case .nexusInsightFormed:
                        self.applyOperationalStateFromNexusInsight(payload: event.payload, timestamp: event.timestamp)
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

                        // Update capability budget/mode snapshot if metadata is attached.
                        self.applyOperationalStateFromToolCompleted(payload: event.payload)

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
                    await MainActor.run {
                        self.latestPressureGraph = graph
                    }
                    cortexStream.updateFromPressureGraph(
                        graph,
                        includeDecisionLayer: self.showDecisionLayerInGraph,
                        hideLowSignalNodes: self.hideLowSignalGraphNodes
                    )
                } else {
                    // 204 No Content is normal during scan initialization
                    // Session may not be fully created yet
                    print(
                        "[AppState] Graph refresh returned nil (204 No Content - session not ready yet)"
                    )
                    await MainActor.run {
                        self.latestPressureGraph = nil
                    }
                }
            } catch {
                // Don't log errors as warnings during scan startup
                // The session initialization race condition is expected
                print("[AppState] Graph refresh failed (expected during scan startup): \(error)")
            }
        }
    }

    func applyGraphLayerVisibility() {
        guard let graph = latestPressureGraph else { return }
        cortexStream.updateFromPressureGraph(
            graph,
            includeDecisionLayer: showDecisionLayerInGraph,
            hideLowSignalNodes: hideLowSignalGraphNodes
        )
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

    /// Refresh tool metadata (tier badges, labels) for the UI.
    func refreshToolMetadata() {
        Task {
            do {
                let meta = try await apiClient.fetchToolMetadata()
                await MainActor.run {
                    self.toolMetadata = meta.tools
                    self.toolModeInfo = meta.modes ?? [:]
                }
            } catch {
                print("[AppState] Tool metadata refresh failed: \(error)")
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
                        // 2. New results have > 0 findings (always accept non-empty data), OR
                        // 3. New results have >= findings count (never go backwards), OR
                        // 4. Scan is not running (allow full replacement when scan is complete)
                        let shouldUpdate =
                            self.apiResults == nil
                            || newFindingsCount > 0  // NEW: Always accept non-zero findings
                            || newFindingsCount >= currentFindingsCount
                            || !self.isScanRunning

                        if shouldUpdate {
                            self.apiResults = results
                            print("[AppState] Results updated: \(newFindingsCount) findings")
                        } else {
                            print(
                                "[AppState] Ignoring empty results: current=\(currentFindingsCount), new=\(newFindingsCount)"
                            )
                        }
                    }
                }
            } catch {
                print("[AppState] Results refresh failed: \(error)")
            }
        }
    }

    // MARK: - Operational State Derivation

    private func applyOperationalStateFromDecision(type: String, evidence: [String: AnyCodable]) {
        // Budget + gate details are surfaced via Strategos RESOURCE_ALLOCATION decisions.
        // We intentionally keep this conservative: only consume keys we expect.
        if let executionMode = evidence["execution_mode"]?.stringValue {
            let tierCeiling = evidence["tier_ceiling"]?.stringValue
            let allowedTiers = (evidence["allowed_tiers"]?.value as? [Any])?.compactMap { "\($0)" } ?? []
            let budget = parseBudgetSnapshot(from: evidence["budget"]?.value)
            self.capabilityGateSnapshot = CapabilityGateSnapshot(
                executionMode: executionMode,
                tierCeiling: tierCeiling,
                allowedTiers: allowedTiers,
                budget: budget
            )
            return
        }

        // Fallback: some decisions only include a scalar budget_remaining.
        if let remaining = evidence["budget_remaining"]?.intValue {
            if let existing = capabilityGateSnapshot, let b = existing.budget {
                let updated = CapabilityBudgetSnapshot(
                    tokensRemaining: remaining,
                    tokensMax: b.tokensMax,
                    timeRemainingS: b.timeRemainingS,
                    timeMaxS: b.timeMaxS,
                    actionsTaken: b.actionsTaken,
                    isExhausted: b.isExhausted
                )
                self.capabilityGateSnapshot = CapabilityGateSnapshot(
                    executionMode: existing.executionMode,
                    tierCeiling: existing.tierCeiling,
                    allowedTiers: existing.allowedTiers,
                    budget: updated
                )
            }
        }
    }

    private func applyOperationalStateFromToolCompleted(payload: [String: AnyCodable]) {
        if let budget = parseBudgetSnapshot(from: payload["budget"]?.value) {
            let executionMode = payload["execution_mode"]?.stringValue
            let tierCeiling = capabilityGateSnapshot?.tierCeiling
            let allowedTiers = capabilityGateSnapshot?.allowedTiers ?? []
            let existingMode = capabilityGateSnapshot?.executionMode

            let mode = executionMode ?? existingMode ?? "unknown"
            self.capabilityGateSnapshot = CapabilityGateSnapshot(
                executionMode: mode,
                tierCeiling: tierCeiling,
                allowedTiers: allowedTiers,
                budget: budget
            )
        }

        // Opportunistic WAF update if tool emits waf metadata.
        if let wafDict = payload["waf"]?.value as? [String: Any],
            let wafName = wafDict["waf_name"] as? String ?? wafDict["waf"] as? String
        {
            self.wafStatus = WAFStatus(wafName: wafName, lastUpdated: Date())
        }
    }

    private func applyOperationalStateFromNexusInsight(payload: [String: AnyCodable], timestamp: Double) {
        let actionType = payload["action_type"]?.stringValue ?? "unknown"
        let summary = payload["summary"]?.stringValue ?? ""
        let target = payload["target"]?.stringValue ?? "unknown"
        let details = payload["details"]?.dictValue ?? [:]

        if (details["p0"] as? Bool) == true {
            let path = details["path"] as? String
            self.activeP0Alert = P0Alert(
                summary: summary,
                target: target,
                path: path,
                createdAt: Date(timeIntervalSince1970: timestamp)
            )
            let text = "🚨 [P0] \(summary)"
            self.apiLogs.append(text)
            self.apiLogItems.append(LogItem(id: UUID(), text: text))
            return
        }

        if actionType == "waf_detected" {
            let wafName =
                (details["waf_name"] as? String)
                ?? (details["waf"] as? String)
                ?? "Unknown WAF"
            self.wafStatus = WAFStatus(wafName: wafName, lastUpdated: Date(timeIntervalSince1970: timestamp))
        }
    }

    private func parseBudgetSnapshot(from any: Any?) -> CapabilityBudgetSnapshot? {
        guard let dict = any as? [String: Any] else { return nil }

        func int(_ key: String) -> Int? {
            if let v = dict[key] as? Int { return v }
            if let v = dict[key] as? Double { return Int(v) }
            if let v = dict[key] as? NSNumber { return v.intValue }
            return nil
        }

        func dbl(_ key: String) -> Double? {
            if let v = dict[key] as? Double { return v }
            if let v = dict[key] as? Int { return Double(v) }
            if let v = dict[key] as? NSNumber { return v.doubleValue }
            return nil
        }

        let tokensRemaining = int("tokens_remaining") ?? 0
        let tokensMax = int("tokens_max") ?? max(tokensRemaining, 1)
        let timeRemainingS = dbl("time_remaining_s") ?? 0.0
        let timeMaxS = dbl("time_max_s") ?? max(timeRemainingS, 1.0)
        let actionsTaken = int("actions_taken")
        let isExhausted =
            (dict["is_exhausted"] as? Bool)
            ?? (dict["is_exhausted"] as? NSNumber).map { $0.boolValue }

        return CapabilityBudgetSnapshot(
            tokensRemaining: tokensRemaining,
            tokensMax: tokensMax,
            timeRemainingS: timeRemainingS,
            timeMaxS: timeMaxS,
            actionsTaken: actionsTaken,
            isExhausted: isExhausted
        )
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

        let sessionID = currentChatSessionID()
        llm.generate(prompt: text, sessionID: sessionID) { [weak self] token in
            guard let self else { return }
            // Update the last message directly
            if var last = self.thread.messages.last, last.role == .assistant {
                last.text += token
                self.thread.messages[self.thread.messages.count - 1] = last
            }
        }
    }

    private func currentChatSessionID() -> String? {
        if let sessionID = apiResults?.scan?.sessionId, !sessionID.isEmpty {
            return sessionID
        }
        if let sessionID = engineStatus?.scanState?.sessionId, !sessionID.isEmpty {
            return sessionID
        }
        if let sessionID = latestPressureGraph?.sessionId, !sessionID.isEmpty {
            return sessionID
        }
        return nil
    }

    /// Function startScan.
    func startScan(
        target: String,
        modules: [String],
        mode: ScanMode,
        personas: [[String: Any]]? = nil,
        oob: [String: Any]? = nil
    ) {
        print("[AppState] startScan invoked target=\(target) mode=\(mode.rawValue)")
        Task {
            do {
                print("[AppState] About to call apiClient.startScan...")
                try await apiClient.startScan(
                    target: target,
                    modules: modules,
                    mode: mode.rawValue,
                    personas: personas,
                    oob: oob
                )
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
        decisions.removeAll()
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
            scanStartTime = Date(timeIntervalSince1970: event.timestamp)
        case .scanCompleted, .scanFailed:
            isScanRunning = false
            scanStartTime = nil
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
            let nodes = cortexStream.nodes.filter { $0.type.lowercased() != "decision" }
            let nodeIds = Set(nodes.map { $0.id })
            let edges = cortexStream.edges.filter { edge in
                nodeIds.contains(edge.source) && nodeIds.contains(edge.target)
            }

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

            // Prefer authoritative entry/critical sets from backend graph DTO when available.
            let backendEntryNodes = (self.latestPressureGraph?.entryNodes ?? [])
                .filter { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
            let backendCriticalNodes = (self.latestPressureGraph?.criticalAssets ?? [])
                .filter { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }

            // Fallback: infer entry nodes from topology if backend values are unavailable.
            var inboundCounts: [String: Int] = [:]
            for node in nodes {
                inboundCounts[node.id] = 0
            }
            for edge in edges {
                inboundCounts[edge.target, default: 0] += 1
            }

            var entryNodes = backendEntryNodes
            if entryNodes.isEmpty {
                entryNodes = nodes
                    .filter { inboundCounts[$0.id, default: 0] == 0 }
                    .map { $0.id }
            }

            if entryNodes.isEmpty {
                let entryTypeHints = ["entry", "target", "exposure", "port", "service", "asset"]
                entryNodes = nodes.filter { node in
                    let lowered = node.type.lowercased()
                    return entryTypeHints.contains { lowered.contains($0) }
                }.map { $0.id }
            }

            if entryNodes.isEmpty, let highestPressure = nodes.max(by: { ($0.pressure ?? 0) < ($1.pressure ?? 0) }) {
                entryNodes = [highestPressure.id]
            }

            // Critical assets fallback = high-pressure sinks; if none, use highest-pressure nodes.
            var criticalNodes = backendCriticalNodes
            if criticalNodes.isEmpty {
                criticalNodes = nodes.filter { ($0.pressure ?? 0) >= 0.7 }.map { $0.id }
            }
            if criticalNodes.isEmpty {
                criticalNodes = nodes
                    .sorted { ($0.pressure ?? 0) > ($1.pressure ?? 0) }
                    .prefix(5)
                    .map { $0.id }
            }

            do {
                let analysis = try await cortexClient.fetchTopology(
                    graph: graphDTO,
                    entryNodes: entryNodes,
                    criticalAssets: criticalNodes
                )

                await MainActor.run {
                    self.graphAnalysis = analysis
                    print(
                        "[Analysis] Received topology: \(analysis.critical_paths?.count ?? 0) critical-path candidates"
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
            let nodes = cortexStream.nodes.filter { $0.type.lowercased() != "decision" }
            let nodeIds = Set(nodes.map { $0.id })
            let edges = cortexStream.edges.filter { edge in
                nodeIds.contains(edge.source) && nodeIds.contains(edge.target)
            }

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
