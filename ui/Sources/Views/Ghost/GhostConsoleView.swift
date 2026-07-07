//
//  GhostConsoleView.swift
//  SentinelForgeUI — Phase 4-UI
//
//  The operator-facing surface for Ghost Protocol. Composes the five
//  Python layers (G1–G5) into a single console:
//
//    * Top bar — status, start/stop, CA cert install hint, port
//    * Left   — captured flows list + recording controls
//    * Right  — selected flow detail (step count, auth tokens) with
//               three action buttons: propose mutations, run replay,
//               cross-principal diff
//    * Sheet  — proposal review + replay-result viewer
//
//  All actions are async; the view polls status every 3 seconds when
//  visible so the operator always sees the current state (running
//  port, flow count, active recordings) without refreshing manually.
//

import SwiftUI


// MARK: - Main view

public struct GhostConsoleView: View {
    @StateObject private var vm = GhostConsoleViewModel()

    public init() {}

    public var body: some View {
        VStack(spacing: 0) {
            statusBar
                .background(Color.black.opacity(0.4))

            HStack(spacing: 0) {
                flowsSidebar
                    .frame(width: 280)
                    .background(Color.black.opacity(0.25))

                Divider()

                flowDetailPane
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .foregroundColor(.white)
        .onAppear { vm.start() }
        .onDisappear { vm.stop() }
        .sheet(item: $vm.activeSheet) { sheet in
            switch sheet {
            case .proposals(let result):
                ProposalReviewSheet(
                    result: result,
                    onReplay: { mutations in
                        vm.replay(mutations: mutations)
                        vm.activeSheet = nil
                    },
                    onClose: { vm.activeSheet = nil }
                )
            case .replayResult(let result):
                ReplayResultSheet(
                    result: result,
                    onClose: { vm.activeSheet = nil }
                )
            case .crossPrincipalInput(let flowId):
                BobIdentitySheet(
                    onRun: { auth, cookie, personaName in
                        vm.activeSheet = nil
                        vm.runCrossPrincipalDiff(
                            flowId: flowId, bobPersonaName: personaName, bobAuth: auth, bobCookie: cookie
                        )
                    },
                    onClose: { vm.activeSheet = nil }
                )
            case .crossPrincipalResult(let diff):
                CrossPrincipalResultSheet(
                    diff: diff,
                    onClose: { vm.activeSheet = nil }
                )
            }
        }
    }

    // MARK: status bar

    private var statusBar: some View {
        HStack(spacing: 16) {
            // Running indicator
            Circle()
                .fill(vm.status?.running == true ? Color.green : Color.red)
                .frame(width: 10, height: 10)

            Text("GHOST PROTOCOL")
                .font(.system(size: 14, weight: .bold, design: .monospaced))
                .foregroundColor(.cyberCyan)

            if let s = vm.status {
                if let port = s.port, s.running {
                    Text("127.0.0.1:\(port)")
                        .font(.system(.body, design: .monospaced))
                        .foregroundColor(.white.opacity(0.85))
                }
                Text("·")
                    .foregroundColor(.white.opacity(0.4))
                Text("\(s.flowCount) flow(s)")
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundColor(.white.opacity(0.65))
                if !s.activeRecordings.isEmpty {
                    Text("· REC: \(s.activeRecordings.joined(separator: ", "))")
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundColor(.red)
                }
            } else {
                Text("loading…")
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundColor(.white.opacity(0.5))
            }

            Spacer()

            if vm.status?.running == true {
                Button(action: { Task { await vm.stopProxy() } }) {
                    Label("Stop", systemImage: "stop.fill")
                }
                .buttonStyle(.borderedProminent)
                .tint(.red)
            } else {
                Button(action: { Task { await vm.startProxy() } }) {
                    Label("Start", systemImage: "play.fill")
                }
                .buttonStyle(.borderedProminent)
                .tint(.green)
            }

            if vm.status?.running == true {
                Button(action: { Task { await vm.launchCaptureBrowser() } }) {
                    Label("Capture Browser", systemImage: "globe")
                }
                .buttonStyle(.bordered)
                .tint(.cyberCyan)
                .disabled(vm.isWorking)
                .help("Open an isolated Chrome routed through Ghost and start recording. "
                    + "Your normal browser and other apps are untouched. HTTPS needs the "
                    + "mitmproxy cert trusted (you'll get one admin prompt the first time).")
            }

            if vm.status?.certAvailable == true, let p = vm.status?.certPath {
                if vm.certTrusted {
                    Button {
                        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: p)])
                    } label: {
                        Label("Cert Trusted", systemImage: "checkmark.shield.fill")
                    }
                    .tint(.green)
                    .help("The mitmproxy CA is trusted in your System keychain — HTTPS sites "
                        + "capture cleanly. Click to reveal the cert in Finder.")
                } else {
                    Button {
                        Task { await vm.trustCert() }
                    } label: {
                        Label("Trust HTTPS Cert", systemImage: "lock.shield")
                    }
                    .disabled(vm.isWorking)
                    .help("Trust the mitmproxy CA in your System keychain (one admin prompt) so "
                        + "HTTPS sites can be captured. Required once; replaces the old "
                        + "reveal-in-Finder step.")
                }
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
    }

    // MARK: flows sidebar

    private var flowsSidebar: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("CAPTURED FLOWS")
                    .font(.system(size: 11, weight: .bold, design: .monospaced))
                    .foregroundColor(.white.opacity(0.65))
                Spacer()
                Button { Task { await vm.refresh() } } label: {
                    Image(systemName: "arrow.clockwise").font(.system(size: 11))
                }
                .buttonStyle(.plain)
                .help("Refresh")
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)

            recordingControls
                .padding(.horizontal, 12)
                .padding(.bottom, 8)

            Divider()

            if vm.flows.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "tray")
                        .font(.system(size: 24))
                        .foregroundColor(.white.opacity(0.3))
                    Text("No flows yet")
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundColor(.white.opacity(0.45))
                    Text("Start the proxy, then click 'Capture Browser' — it opens an isolated Chrome routed through Ghost and records as you browse. (Or name a flow and hit ⏺ to record manually.)")
                        .font(.system(size: 11))
                        .foregroundColor(.white.opacity(0.35))
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 16)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(spacing: 4) {
                        ForEach(vm.flows) { flow in
                            flowRow(flow)
                        }
                    }
                    .padding(.vertical, 8)
                }
            }
        }
    }

    private var recordingControls: some View {
        VStack(spacing: 8) {
            HStack {
                TextField("flow name", text: $vm.newFlowName)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 12, design: .monospaced))
                    // Always typeable — naming a flow before/while the proxy
                    // spins up is harmless, and gating on the *polled* status
                    // made the field dead until the next 3s refresh landed.
                    // Only the record action itself requires a running proxy.
                Button {
                    Task { await vm.startRecording() }
                } label: {
                    Image(systemName: "record.circle")
                        .foregroundColor(.red)
                }
                .buttonStyle(.bordered)
                .disabled(vm.status?.running != true || vm.newFlowName.isEmpty)
                .help("Start recording a named flow")
            }
            if let active = vm.status?.activeRecordings, !active.isEmpty {
                HStack(spacing: 6) {
                    Text("Stopping:")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.white.opacity(0.6))
                    ForEach(active, id: \.self) { name in
                        Button(name) { Task { await vm.stopRecording(name) } }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                    }
                }
            }
        }
    }

    private func flowRow(_ flow: GhostFlowSummary) -> some View {
        Button(action: { vm.selectedFlowId = flow.flowId }) {
            HStack(spacing: 8) {
                Image(systemName: flow.hasAuthTokens
                      ? "lock.fill" : "lock.open.fill")
                    .foregroundColor(flow.hasAuthTokens
                                     ? .cyberCyan : .white.opacity(0.4))
                    .font(.system(size: 12))
                VStack(alignment: .leading, spacing: 2) {
                    Text(flow.name)
                        .font(.system(size: 13, weight: .medium, design: .monospaced))
                        .foregroundColor(.white)
                    Text("\(flow.stepCount) step(s) · \(flow.flowId.prefix(8))")
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.white.opacity(0.45))
                }
                Spacer()
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .background(
                vm.selectedFlowId == flow.flowId
                    ? Color.cyberBlue.opacity(0.25)
                    : Color.clear
            )
            .cornerRadius(6)
        }
        .buttonStyle(.plain)
        .padding(.horizontal, 8)
    }

    // MARK: flow detail pane

    @ViewBuilder
    private var flowDetailPane: some View {
        if let flow = vm.selectedFlow {
            VStack(alignment: .leading, spacing: 16) {
                Text(flow.name)
                    .font(.system(size: 22, weight: .bold, design: .monospaced))
                    .foregroundColor(.cyberCyan)

                HStack(spacing: 24) {
                    statLabel("STEPS", value: "\(flow.stepCount)")
                    statLabel(
                        "AUTH",
                        value: flow.hasAuthTokens ? "captured" : "anonymous"
                    )
                    statLabel("FLOW ID", value: String(flow.flowId.prefix(12)))
                }
                .padding(.horizontal, 4)

                Divider()

                Text("ACTIONS")
                    .font(.system(size: 11, weight: .bold, design: .monospaced))
                    .foregroundColor(.white.opacity(0.6))

                HStack(spacing: 12) {
                    actionButton(
                        title: "Propose Mutations",
                        systemImage: "wand.and.stars",
                        color: .purple,
                        help: "Inspect this flow's steps and surface relevant vulnerability hypotheses (G4)"
                    ) {
                        Task { await vm.propose() }
                    }
                    actionButton(
                        title: "Run Replay",
                        systemImage: "play.rectangle.fill",
                        color: .green,
                        help: "Replay this flow with no mutations — sanity check, then run with mutations from the proposals"
                    ) {
                        Task { await vm.replay(mutations: []) }
                    }
                    actionButton(
                        title: "Cross-Principal Diff",
                        systemImage: "person.2.fill",
                        color: .orange,
                        help: "Replay this flow under a second identity (Bob) and surface cross-principal IDOR/BOLA (G5). You supply Bob's auth token or cookie."
                    ) {
                        vm.activeSheet = .crossPrincipalInput(flowId: flow.flowId)
                    }
                }

                if vm.isWorking {
                    HStack(spacing: 8) {
                        ProgressView().controlSize(.small)
                        Text(vm.workingLabel)
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundColor(.white.opacity(0.6))
                    }
                }

                if let err = vm.errorMessage {
                    Text(err)
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundColor(.red)
                        .padding(.top, 8)
                }

                Spacer()
            }
            .padding(24)
            .frame(maxWidth: .infinity, alignment: .leading)
        } else {
            VStack(spacing: 12) {
                Image(systemName: "eye.slash.fill")
                    .font(.system(size: 36))
                    .foregroundColor(.white.opacity(0.25))
                Text("Select a flow")
                    .font(.system(size: 14, design: .monospaced))
                    .foregroundColor(.white.opacity(0.5))
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private func statLabel(_ label: String, value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.system(size: 10, weight: .bold, design: .monospaced))
                .foregroundColor(.white.opacity(0.5))
            Text(value)
                .font(.system(size: 16, weight: .semibold, design: .monospaced))
                .foregroundColor(.white)
        }
    }

    private func actionButton(
        title: String,
        systemImage: String,
        color: Color,
        help: String,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            HStack(spacing: 8) {
                Image(systemName: systemImage)
                Text(title)
                    .font(.system(size: 13, weight: .medium, design: .monospaced))
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 8)
            .background(color.opacity(0.85))
            .cornerRadius(6)
            .foregroundColor(.white)
        }
        .buttonStyle(.plain)
        .help(help)
        .disabled(vm.isWorking)
    }
}


// MARK: - View model

@MainActor
final class GhostConsoleViewModel: ObservableObject {
    @Published var status: GhostStatus?
    @Published var flows: [GhostFlowSummary] = []
    @Published var selectedFlowId: String?
    @Published var newFlowName: String = ""
    @Published var isWorking: Bool = false
    @Published var workingLabel: String = ""
    @Published var errorMessage: String?
    @Published var activeSheet: ActiveSheet?
    @Published var certTrusted: Bool = false

    enum ActiveSheet: Identifiable {
        case proposals(GhostProposeResult)
        case replayResult(GhostReplayResult)
        case crossPrincipalInput(flowId: String)
        case crossPrincipalResult(GhostCrossPrincipalDiff)

        var id: String {
            switch self {
            case .proposals: return "proposals"
            case .replayResult: return "replay"
            case .crossPrincipalInput: return "xpInput"
            case .crossPrincipalResult: return "xpResult"
            }
        }
    }

    private var pollTask: Task<Void, Never>?
    private let client = GhostAPIClient.shared

    var selectedFlow: GhostFlowSummary? {
        guard let id = selectedFlowId else { return nil }
        return flows.first(where: { $0.flowId == id })
    }

    func start() {
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refresh()
                try? await Task.sleep(nanoseconds: 3_000_000_000)
            }
        }
    }

    func stop() {
        pollTask?.cancel()
        pollTask = nil
    }

    func refresh() async {
        do {
            let s = try await client.status()
            self.status = s
            self.flows = try await client.listFlows()
        } catch {
            self.errorMessage = "Refresh failed: \(error.localizedDescription)"
        }

        // Refresh CA-trust state only while still untrusted, so the poll
        // loop stops spawning `security` once the cert is in the keychain.
        if status?.certAvailable == true, !certTrusted {
            let trusted = (try? await runOffMain { GhostCaptureBrowser.isCertTrusted() }) ?? false
            self.certTrusted = trusted
        }
    }

    /// Trust the mitmproxy CA in the System keychain (one admin prompt) so
    /// HTTPS sites are interceptable. Idempotent — safe to click again.
    func trustCert() async {
        let certPath = status?.certPath
        isWorking = true
        workingLabel = "Trusting HTTPS cert…"
        defer { isWorking = false; workingLabel = "" }
        do {
            try await runOffMain {
                if !GhostCaptureBrowser.isCertTrusted() {
                    try GhostCaptureBrowser.trustCert(certPath: certPath)
                }
            }
            certTrusted = true
            errorMessage = nil
        } catch let e as GhostCaptureBrowserError {
            errorMessage = e.errorDescription
        } catch {
            errorMessage = "Cert trust failed: \(error.localizedDescription)"
        }
    }

    func startProxy() async {
        isWorking = true
        workingLabel = "Starting proxy…"
        defer { isWorking = false; workingLabel = "" }
        do {
            _ = try await client.start(port: 0)
            await refresh()
        } catch {
            errorMessage = "Start failed: \(error.localizedDescription)"
        }
    }

    func stopProxy() async {
        isWorking = true
        workingLabel = "Stopping proxy…"
        defer { isWorking = false; workingLabel = "" }
        do {
            _ = try await client.stop()
            await refresh()
        } catch {
            errorMessage = "Stop failed: \(error.localizedDescription)"
        }
    }

    /// One-click capture: ensure the mitmproxy CA is trusted (HTTPS), make
    /// sure a recording is active so flows actually capture, then open an
    /// isolated Chrome routed through the Ghost proxy. This is the "last mile"
    /// that was previously missing — starting the proxy alone records nothing
    /// because no browser was ever pointed at it.
    func launchCaptureBrowser() async {
        guard let port = status?.port, status?.running == true else {
            errorMessage = "Start the proxy first (click Start)."
            return
        }
        let certPath = status?.certPath
        let hadActiveRecording = !(status?.activeRecordings.isEmpty ?? true)

        isWorking = true
        workingLabel = "Preparing capture browser…"
        defer { isWorking = false; workingLabel = "" }

        do {
            // 1. Trust the mitmproxy CA so HTTPS sites are interceptable.
            //    Off the main thread: the admin prompt is modal and blocking.
            workingLabel = "Checking HTTPS cert…"
            try await runOffMain {
                if !GhostCaptureBrowser.isCertTrusted() {
                    try GhostCaptureBrowser.trustCert(certPath: certPath)
                }
            }
            certTrusted = true

            // 2. Auto-start a recording if none is active — otherwise the
            //    proxy sees traffic but the flows list stays empty.
            if !hadActiveRecording {
                try await client.startRecording("capture-\(Self.captureTimestamp())")
            }

            // 3. Launch the isolated, proxied browser.
            workingLabel = "Opening capture browser…"
            let browserName = try await runOffMain {
                try GhostCaptureBrowser.launchCaptureBrowser(proxyPort: port)
            }

            errorMessage = nil
            workingLabel = "\(browserName) launched — browse to capture"
            await refresh()
        } catch let e as GhostCaptureBrowserError {
            errorMessage = e.errorDescription
        } catch {
            errorMessage = "Capture browser failed: \(error.localizedDescription)"
        }
    }

    /// Run blocking work (Process calls, admin dialog) off the main actor so
    /// the UI stays responsive while the capture browser spins up.
    private func runOffMain<T>(_ work: @escaping () throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { cont in
            DispatchQueue.global(qos: .userInitiated).async {
                do { cont.resume(returning: try work()) }
                catch { cont.resume(throwing: error) }
            }
        }
    }

    private static func captureTimestamp() -> String {
        let f = DateFormatter()
        f.dateFormat = "HHmmss"
        return f.string(from: Date())
    }

    func startRecording() async {
        let name = newFlowName.trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty else { return }
        do {
            try await client.startRecording(name)
            newFlowName = ""
            await refresh()
        } catch {
            errorMessage = "Recording failed: \(error.localizedDescription)"
        }
    }

    func stopRecording(_ name: String) async {
        do {
            try await client.stopRecording(name)
            await refresh()
        } catch {
            errorMessage = "Stop recording failed: \(error.localizedDescription)"
        }
    }

    func propose() async {
        guard let id = selectedFlowId else { return }
        isWorking = true
        workingLabel = "Generating mutation proposals…"
        defer { isWorking = false; workingLabel = "" }
        do {
            let r = try await client.proposeFor(flowId: id)
            self.activeSheet = .proposals(r)
        } catch {
            errorMessage = "Propose failed: \(error.localizedDescription)"
        }
    }

    func replay(mutations: [GhostMutationSpec]) {
        Task { [weak self] in
            guard let self = self else { return }
            await self.runReplay(mutations: mutations)
        }
    }

    private func runReplay(mutations: [GhostMutationSpec]) async {
        guard let id = selectedFlowId else { return }
        isWorking = true
        workingLabel = "Replaying flow with \(mutations.count) mutation(s)…"
        defer { isWorking = false; workingLabel = "" }
        do {
            let r = try await client.replayFlow(
                flowId: id, mutations: mutations
            )
            self.activeSheet = .replayResult(r)
        } catch {
            errorMessage = "Replay failed: \(error.localizedDescription)"
        }
    }

    // MARK: cross-principal diff (G5)

    func runCrossPrincipalDiff(flowId: String, bobPersonaName: String, bobAuth: String, bobCookie: String) {
        Task { [weak self] in
            await self?.executeCrossPrincipalDiff(
                flowId: flowId, bobPersonaName: bobPersonaName, bobAuth: bobAuth, bobCookie: bobCookie
            )
        }
    }

    private func executeCrossPrincipalDiff(
        flowId: String, bobPersonaName: String, bobAuth: String, bobCookie: String
    ) async {
        isWorking = true
        workingLabel = "Replaying flow as Bob…"
        defer { isWorking = false; workingLabel = "" }

        // Bob's auth: accept a raw token or a full "Bearer …" value.
        var headers: [String: String] = [:]
        let auth = bobAuth.trimmingCharacters(in: .whitespacesAndNewlines)
        if !auth.isEmpty {
            headers["Authorization"] = auth.lowercased().hasPrefix("bearer ")
                ? auth : "Bearer \(auth)"
        }
        // Bob's cookies: parse a "k=v; k2=v2" string into a dict.
        var cookies: [String: String] = [:]
        let cookieStr = bobCookie.trimmingCharacters(in: .whitespacesAndNewlines)
        if !cookieStr.isEmpty {
            for pair in cookieStr.split(separator: ";") {
                let kv = pair.split(separator: "=", maxSplits: 1).map {
                    $0.trimmingCharacters(in: .whitespaces)
                }
                if kv.count == 2 { cookies[kv[0]] = kv[1] }
            }
        }

        guard !headers.isEmpty || !cookies.isEmpty else {
            errorMessage = "Provide Bob's auth token or a cookie to run the diff."
            return
        }

        do {
            let diff = try await client.crossPrincipalDiff(
                flowId: flowId, bobPersonaName: bobPersonaName, bobHeaders: headers, bobCookies: cookies
            )
            self.activeSheet = .crossPrincipalResult(diff)
            errorMessage = nil
        } catch {
            errorMessage = "Cross-principal diff failed: \(error.localizedDescription)"
        }
    }
}


// MARK: - Proposal review sheet

private struct ProposalReviewSheet: View {
    let result: GhostProposeResult
    let onReplay: ([GhostMutationSpec]) -> Void
    let onClose: () -> Void

    @State private var selected: Set<String> = []

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("Mutation Proposals")
                    .font(.system(size: 18, weight: .bold, design: .monospaced))
                    .foregroundColor(.cyberCyan)
                Spacer()
                Button("Close") { onClose() }
            }
            .padding()

            Divider()

            Text("\(result.proposalCount) proposals across \(result.stepCount) step(s) in '\(result.flowName)'")
                .font(.system(size: 12, design: .monospaced))
                .foregroundColor(.white.opacity(0.65))
                .padding(.horizontal)
                .padding(.top, 8)

            ScrollView {
                LazyVStack(spacing: 6) {
                    ForEach(result.proposals) { p in
                        ProposalRow(proposal: p, isSelected: selected.contains(p.id))
                            .onTapGesture {
                                if selected.contains(p.id) {
                                    selected.remove(p.id)
                                } else {
                                    selected.insert(p.id)
                                }
                            }
                    }
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 8)
            }

            Divider()

            HStack {
                Text("\(selected.count) selected")
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundColor(.white.opacity(0.65))
                Spacer()
                Button("Select All") { selected = Set(result.proposals.map { $0.id }) }
                Button("Clear") { selected.removeAll() }
                Button("Run Replay") {
                    let specs = result.proposals
                        .filter { selected.contains($0.id) }
                        .map { GhostMutationSpec(
                            stepIndex: $0.stepIndex,
                            mutation: $0.mutationLabel
                        )}
                    onReplay(specs)
                }
                .buttonStyle(.borderedProminent)
                .disabled(selected.isEmpty)
            }
            .padding()
        }
        .frame(minWidth: 700, minHeight: 500)
        .background(Color(red: 0.05, green: 0.05, blue: 0.08))
        .foregroundColor(.white)
    }
}

private struct ProposalRow: View {
    let proposal: GhostMutationProposal
    let isSelected: Bool

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: isSelected ? "checkmark.square.fill" : "square")
                .foregroundColor(isSelected ? .cyberCyan : .white.opacity(0.4))
                .font(.system(size: 14))
                .padding(.top, 2)
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Text("step \(proposal.stepIndex)")
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.white.opacity(0.5))
                    Text(proposal.mutationLabel)
                        .font(.system(size: 13, weight: .bold, design: .monospaced))
                        .foregroundColor(.cyberCyan)
                    Text("\(proposal.stepMethod) \(proposal.stepUrl)")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.white.opacity(0.55))
                        .lineLimit(1)
                }
                Text(proposal.rationale)
                    .font(.system(size: 11))
                    .foregroundColor(.white.opacity(0.75))
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
        }
        .padding(.vertical, 8)
        .padding(.horizontal, 12)
        .background(
            isSelected
                ? Color.cyberBlue.opacity(0.18)
                : Color.white.opacity(0.04)
        )
        .cornerRadius(6)
    }
}


// MARK: - Replay result sheet

private struct ReplayResultSheet: View {
    let result: GhostReplayResult
    let onClose: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Replay Result")
                        .font(.system(size: 18, weight: .bold, design: .monospaced))
                        .foregroundColor(.cyberCyan)
                    Text(result.sourceFlowName)
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundColor(.white.opacity(0.65))
                }
                Spacer()
                Button("Close") { onClose() }
            }
            .padding()

            Divider()

            HStack(spacing: 24) {
                VStack(alignment: .leading) {
                    Text("STEPS").font(.system(size: 10, weight: .bold, design: .monospaced)).foregroundColor(.white.opacity(0.5))
                    Text("\(result.stepDiffs.count)").font(.system(size: 18, design: .monospaced))
                }
                VStack(alignment: .leading) {
                    Text("DIVERGED").font(.system(size: 10, weight: .bold, design: .monospaced)).foregroundColor(.white.opacity(0.5))
                    Text("\(result.divergedStepCount)").font(.system(size: 18, design: .monospaced))
                        .foregroundColor(result.divergedStepCount > 0 ? .orange : .green)
                }
                VStack(alignment: .leading) {
                    Text("WALLCLOCK").font(.system(size: 10, weight: .bold, design: .monospaced)).foregroundColor(.white.opacity(0.5))
                    Text("\(Int(result.totalElapsedMs))ms").font(.system(size: 18, design: .monospaced))
                }
                if result.stoppedEarly {
                    VStack(alignment: .leading) {
                        Text("HALTED").font(.system(size: 10, weight: .bold, design: .monospaced)).foregroundColor(.orange)
                        Text("yes").font(.system(size: 18, design: .monospaced)).foregroundColor(.orange)
                    }
                }
                Spacer()
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)

            Divider()

            ScrollView {
                LazyVStack(spacing: 6) {
                    ForEach(result.stepDiffs) { diff in
                        StepDiffRow(diff: diff)
                    }
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 8)
            }
        }
        .frame(minWidth: 800, minHeight: 600)
        .background(Color(red: 0.05, green: 0.05, blue: 0.08))
        .foregroundColor(.white)
    }
}

private struct StepDiffRow: View {
    let diff: GhostStepDiff

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: diff.diverged ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                .foregroundColor(diff.diverged ? .orange : .green)
                .font(.system(size: 14))
                .padding(.top, 2)
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Text("step \(diff.stepIndex)")
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.white.opacity(0.5))
                    Text("\(diff.method) \(diff.url)")
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundColor(.white.opacity(0.85))
                        .lineLimit(1)
                }
                HStack(spacing: 12) {
                    Text("status: \(diff.originalStatus) → \(diff.replayStatus)")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(
                            diff.statusChanged ? .orange : .white.opacity(0.55)
                        )
                    Text("size: \(diff.originalSize) → \(diff.replaySize) (Δ\(diff.sizeDelta))")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(
                            diff.bodyChanged ? .orange : .white.opacity(0.55)
                        )
                    if !diff.appliedMutations.isEmpty {
                        Text("μ \(diff.appliedMutations.joined(separator: ", "))")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(.purple)
                    }
                }
            }
            Spacer()
        }
        .padding(.vertical, 8)
        .padding(.horizontal, 12)
        .background(diff.diverged
            ? Color.orange.opacity(0.10)
            : Color.white.opacity(0.04)
        )
        .cornerRadius(6)
    }
}


// MARK: - Cross-principal diff (G5): Bob identity input

private struct BobIdentitySheet: View {
    /// (authToken, cookieString, personaName)
    let onRun: (String, String, String) -> Void
    let onClose: () -> Void

    @State private var auth: String = ""
    @State private var cookie: String = ""
    
    // Foundry integration
    @State private var selectedPersonaName: String = "bob"
    @State private var availablePersonas: [FoundryPersona] = []
    @State private var isFetchingPersonas = false

    private var canRun: Bool {
        !auth.trimmingCharacters(in: .whitespaces).isEmpty
            || !cookie.trimmingCharacters(in: .whitespaces).isEmpty
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Cross-Principal Diff")
                        .font(.system(size: 18, weight: .bold, design: .monospaced))
                        .foregroundColor(.cyberCyan)
                    Text("Replay this flow as a second identity (Bob)")
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundColor(.white.opacity(0.6))
                }
                Spacer()
                Button("Cancel") { onClose() }
            }

            Text("The captured flow plays as Alice. Paste Bob's session below — every request is re-issued as Bob, and any step where Bob receives Alice's data is flagged as IDOR/BOLA.")
                .font(.system(size: 12))
                .foregroundColor(.white.opacity(0.75))
                .fixedSize(horizontal: false, vertical: true)
                
            HStack {
                Text("ATTRIBUTION PERSONA (from Foundry)")
                    .font(.system(size: 10, weight: .bold, design: .monospaced))
                    .foregroundColor(.white.opacity(0.55))
                Spacer()
                if isFetchingPersonas {
                    ProgressView().controlSize(.small)
                } else {
                    Button(action: fetchPersonas) {
                        Image(systemName: "arrow.triangle.2.circlepath")
                    }
                    .buttonStyle(.plain)
                    .help("Refresh Personas from Foundry")
                }
            }
            
            if !availablePersonas.isEmpty {
                Picker("", selection: $selectedPersonaName) {
                    Text("Default (bob)").tag("bob")
                    ForEach(availablePersonas) { p in
                        Text(p.label).tag(p.label)
                    }
                }
                .pickerStyle(.menu)
                .labelsHidden()
                .frame(maxWidth: .infinity, alignment: .leading)
            } else {
                Text("No personas found in vault. Defaulting to 'bob'.")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(.white.opacity(0.4))
            }

            VStack(alignment: .leading, spacing: 6) {
                Text("BOB'S AUTH TOKEN")
                    .font(.system(size: 10, weight: .bold, design: .monospaced))
                    .foregroundColor(.white.opacity(0.55))
                TextField("Bearer eyJ…  (or just the raw token)", text: $auth)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 12, design: .monospaced))
                Text("Sent as the Authorization header, replacing Alice's.")
                    .font(.system(size: 10))
                    .foregroundColor(.white.opacity(0.4))
            }

            VStack(alignment: .leading, spacing: 6) {
                Text("BOB'S COOKIES (optional)")
                    .font(.system(size: 10, weight: .bold, design: .monospaced))
                    .foregroundColor(.white.opacity(0.55))
                TextField("session=…; other=…", text: $cookie)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 12, design: .monospaced))
                Text("For cookie-based auth. Format: name=value; name2=value2")
                    .font(.system(size: 10))
                    .foregroundColor(.white.opacity(0.4))
            }

            HStack {
                Spacer()
                Button { onRun(auth, cookie, selectedPersonaName) } label: {
                    Label("Run Diff", systemImage: "person.2.fill")
                }
                .buttonStyle(.borderedProminent)
                .tint(.orange)
                .disabled(!canRun)
            }
        }
        .padding(24)
        .frame(minWidth: 560, minHeight: 400)
        .background(Color(red: 0.05, green: 0.05, blue: 0.08))
        .foregroundColor(.white)
        .onAppear {
            if availablePersonas.isEmpty { fetchPersonas() }
        }
    }
    
    private func fetchPersonas() {
        isFetchingPersonas = true
        Task {
            do {
                let fetched = try await FoundryAPIClient.shared.listPersonas()
                await MainActor.run {
                    self.availablePersonas = fetched
                    self.isFetchingPersonas = false
                }
            } catch {
                print("[BobIdentitySheet] Error fetching personas: \(error)")
                await MainActor.run { self.isFetchingPersonas = false }
            }
        }
    }
}


// MARK: - Cross-principal diff (G5): result

private struct CrossPrincipalResultSheet: View {
    let diff: GhostCrossPrincipalDiff
    let onClose: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Cross-Principal Diff")
                        .font(.system(size: 18, weight: .bold, design: .monospaced))
                        .foregroundColor(.cyberCyan)
                    Text("\(diff.alicePersona) → \(diff.bobPersona) · \(diff.sourceFlowName)")
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundColor(.white.opacity(0.65))
                }
                Spacer()
                Button("Close") { onClose() }
            }
            .padding()

            Divider()

            HStack(spacing: 24) {
                stat("IDOR STEPS", "\(diff.idorStepCount)",
                     color: diff.idorStepCount > 0 ? .red : .green)
                stat("DENIED", "\(diff.deniedStepCount)", color: .green)
                stat("STEPS", "\(diff.stepFindings.count)", color: .white)
                stat("WALLCLOCK", "\(Int(diff.totalElapsedMs))ms", color: .white)
                Spacer()
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)

            if diff.idorStepCount > 0 {
                Text("⚠︎ Bob reached Alice's data — likely broken object-level authorization (IDOR/BOLA).")
                    .font(.system(size: 12, weight: .medium))
                    .foregroundColor(.red)
                    .padding(.horizontal, 16)
                    .padding(.bottom, 8)
            }

            Divider()

            if diff.stepFindings.isEmpty {
                Spacer()
                Text("No steps to compare.")
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundColor(.white.opacity(0.5))
                    .frame(maxWidth: .infinity)
                Spacer()
            } else {
                ScrollView {
                    LazyVStack(spacing: 6) {
                        ForEach(diff.stepFindings) { f in
                            CrossPrincipalStepRow(finding: f)
                        }
                    }
                    .padding(.horizontal, 16)
                    .padding(.vertical, 8)
                }
            }
        }
        .frame(minWidth: 820, minHeight: 600)
        .background(Color(red: 0.05, green: 0.05, blue: 0.08))
        .foregroundColor(.white)
    }

    private func stat(_ label: String, _ value: String, color: Color) -> some View {
        VStack(alignment: .leading) {
            Text(label)
                .font(.system(size: 10, weight: .bold, design: .monospaced))
                .foregroundColor(.white.opacity(0.5))
            Text(value)
                .font(.system(size: 20, design: .monospaced))
                .foregroundColor(color)
        }
    }
}

private struct CrossPrincipalStepRow: View {
    let finding: GhostCrossPrincipalStep

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Image(systemName: finding.isIdorSignal
                      ? "exclamationmark.triangle.fill" : "checkmark.shield.fill")
                    .foregroundColor(finding.isIdorSignal ? .red : .green)
                    .font(.system(size: 13))
                Text("\(finding.method) \(finding.url)")
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundColor(.white.opacity(0.9))
                    .lineLimit(1)
                Spacer()
                Text(finding.signal)
                    .font(.system(size: 10, weight: .bold, design: .monospaced))
                    .padding(.horizontal, 6).padding(.vertical, 2)
                    .background(finding.isIdorSignal
                                ? Color.red.opacity(0.25) : Color.white.opacity(0.08))
                    .cornerRadius(4)
                Text(String(format: "%.0f%%", finding.confidence * 100))
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(finding.isIdorSignal ? .red : .white.opacity(0.5))
            }
            Text("alice \(finding.aliceStatus)/\(finding.aliceBodySize)b  →  bob \(finding.bobStatus)/\(finding.bobBodySize)b")
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(.white.opacity(0.55))
            Text(finding.rationale)
                .font(.system(size: 11))
                .foregroundColor(.white.opacity(0.75))
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.vertical, 8)
        .padding(.horizontal, 12)
        .background(finding.isIdorSignal
                    ? Color.red.opacity(0.10) : Color.white.opacity(0.04))
        .cornerRadius(6)
    }
}
