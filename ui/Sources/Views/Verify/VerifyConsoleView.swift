//
//  VerifyConsoleView.swift
//  SentinelForgeUI — Phase 5-VC4
//
//  The operator-facing surface for the Verify Console. Three panels:
//    * Top — scope banner (read-only allowlist + Add-Scope button) +
//            finding context (vuln class, payload, target URL).
//    * Left — request builder (method, URL, headers, body) with a
//            big Send button. Errors (notably 403 out-of-scope) get
//            an inline banner with a one-click "Add to scope" CTA.
//    * Right — transcript of captured exchanges. Each row has a
//            checkbox so the operator can select which exchanges
//            promote to repro. The Promote button at the bottom
//            renders the selected subset as bounty-report-ready
//            markdown.
//
//  The Verify Console deliberately doesn't try to replace the
//  long-running-tool TerminalView — they coexist. Verify Console is
//  for SURGICAL HTTP probes against a confirmed finding; TerminalView
//  is for streaming output of nuclei/nmap/etc.
//

import SwiftUI

public struct VerifyConsoleView: View {
    @StateObject private var vm = VerifyConsoleViewModel()

    public init() {}

    public var body: some View {
        VStack(spacing: 0) {
            topBar
            scopeBar

            Divider()

            HStack(spacing: 0) {
                requestBuilderPane
                    .frame(width: 360)
                    .background(Color.black.opacity(0.25))

                Divider()

                transcriptPane
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .foregroundColor(.white)
        .onAppear { vm.start() }
        .onDisappear { vm.stop() }
        .sheet(item: $vm.promoteResult) { result in
            PromoteResultSheet(
                result: result,
                onClose: { vm.promoteResult = nil }
            )
        }
        .alert("Scope violation", isPresented: $vm.scopeAlertVisible) {
            Button("Add to scope") {
                Task { await vm.confirmAddRejectedToScope() }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(vm.scopeAlertMessage)
        }
    }

    // MARK: top bar

    private var topBar: some View {
        HStack(spacing: 16) {
            Image(systemName: "checkmark.shield.fill")
                .foregroundColor(.cyberCyan)
                .font(.system(size: 16))
            VStack(alignment: .leading, spacing: 2) {
                Text("VERIFY CONSOLE")
                    .font(.system(size: 14, weight: .bold, design: .monospaced))
                    .foregroundColor(.cyberCyan)
                if let f = vm.session?.originalFindingSummary {
                    Text("\(f.vulnClass ?? "?") · \(f.payload ?? "no payload") · conf \(String(format: "%.2f", f.confidence ?? 0))")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.white.opacity(0.65))
                } else if vm.session != nil {
                    Text("ad-hoc verification (no finding bound)")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.white.opacity(0.5))
                }
            }
            Spacer()

            Picker("Session", selection: $vm.selectedSessionId) {
                Text("New session…").tag(String?.none)
                ForEach(vm.sessions) { s in
                    Text("\(s.findingId ?? "ad-hoc") · \(s.targetUrl)")
                        .tag(s.sessionId as String?)
                }
            }
            .pickerStyle(.menu)
            .frame(maxWidth: 360)

            Button { Task { await vm.openNewSessionSheet() } } label: {
                Image(systemName: "plus.circle.fill")
            }
            .buttonStyle(.plain)
            .help("Create a new VerificationSession")
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .background(Color.black.opacity(0.4))
    }

    // MARK: scope bar

    private var scopeBar: some View {
        HStack(spacing: 12) {
            Image(systemName: "lock.shield.fill")
                .foregroundColor(.green)
                .font(.system(size: 12))
            Text("SCOPE")
                .font(.system(size: 10, weight: .bold, design: .monospaced))
                .foregroundColor(.white.opacity(0.65))
            if let s = vm.session {
                ForEach(s.allowedOrigins, id: \.self) { origin in
                    Text(origin)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.green)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Color.green.opacity(0.12))
                        .cornerRadius(4)
                }
            } else {
                Text("(no session)")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(.white.opacity(0.4))
            }
            Spacer()
            Button {
                Task { await vm.openAddScopeSheet() }
            } label: {
                Label("Add origin", systemImage: "plus.rectangle")
                    .font(.system(size: 11, design: .monospaced))
            }
            .buttonStyle(.bordered)
            .controlSize(.small)
            .disabled(vm.session == nil)
            .help("Explicitly extend scope to another origin (the only way to grow it)")
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
    }

    // MARK: request builder

    private var requestBuilderPane: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("REQUEST")
                .font(.system(size: 11, weight: .bold, design: .monospaced))
                .foregroundColor(.white.opacity(0.65))
                .padding(.top, 12)
                .padding(.horizontal, 16)

            HStack(spacing: 8) {
                Picker("Method", selection: $vm.requestMethod) {
                    ForEach(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"], id: \.self) { Text($0) }
                }
                .pickerStyle(.menu)
                .frame(width: 100)
                TextField("URL (e.g. https://target/api/users/2)", text: $vm.requestURL)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 12, design: .monospaced))
            }
            .padding(.horizontal, 16)

            VStack(alignment: .leading, spacing: 4) {
                Text("HEADERS (one per line: Name: Value)")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(.white.opacity(0.5))
                TextEditor(text: $vm.requestHeadersRaw)
                    .font(.system(size: 12, design: .monospaced))
                    .frame(minHeight: 70, maxHeight: 100)
                    .border(Color.white.opacity(0.15))
            }
            .padding(.horizontal, 16)

            VStack(alignment: .leading, spacing: 4) {
                Text("BODY (raw)")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(.white.opacity(0.5))
                TextEditor(text: $vm.requestBody)
                    .font(.system(size: 12, design: .monospaced))
                    .frame(minHeight: 80, maxHeight: 150)
                    .border(Color.white.opacity(0.15))
            }
            .padding(.horizontal, 16)

            HStack {
                if vm.isSending {
                    ProgressView().controlSize(.small)
                    Text("sending…").font(.system(size: 11, design: .monospaced)).foregroundColor(.white.opacity(0.65))
                }
                Spacer()
                Button {
                    Task { await vm.sendRequest() }
                } label: {
                    Label("Send", systemImage: "paperplane.fill")
                }
                .buttonStyle(.borderedProminent)
                .tint(.green)
                .disabled(vm.session == nil || vm.requestURL.isEmpty || vm.isSending)
            }
            .padding(.horizontal, 16)

            if let err = vm.errorMessage {
                Text(err)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(.red)
                    .padding(.horizontal, 16)
                    .padding(.bottom, 8)
            }

            Spacer()
        }
    }

    // MARK: transcript

    private var transcriptPane: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("TRANSCRIPT")
                    .font(.system(size: 11, weight: .bold, design: .monospaced))
                    .foregroundColor(.white.opacity(0.65))
                Text("\(vm.session?.transcript.count ?? 0) exchange(s)")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(.white.opacity(0.45))
                Spacer()
                if !vm.selectedExchangeIndices.isEmpty {
                    Text("\(vm.selectedExchangeIndices.count) selected")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.cyberCyan)
                }
                Button {
                    Task { await vm.promoteSelected() }
                } label: {
                    Label("Promote to Repro", systemImage: "doc.text.fill")
                }
                .buttonStyle(.borderedProminent)
                .tint(.purple)
                .controlSize(.regular)
                .disabled(vm.selectedExchangeIndices.isEmpty)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)

            Divider()

            if let s = vm.session, !s.transcript.isEmpty {
                ScrollView {
                    LazyVStack(spacing: 6) {
                        ForEach(Array(s.transcript.enumerated()), id: \.offset) { idx, ex in
                            ExchangeRow(
                                index: idx,
                                exchange: ex,
                                isSelected: vm.selectedExchangeIndices.contains(idx),
                                onToggle: {
                                    if vm.selectedExchangeIndices.contains(idx) {
                                        vm.selectedExchangeIndices.remove(idx)
                                    } else {
                                        vm.selectedExchangeIndices.insert(idx)
                                    }
                                }
                            )
                        }
                    }
                    .padding(16)
                }
            } else {
                VStack(spacing: 8) {
                    Image(systemName: "tray")
                        .font(.system(size: 32))
                        .foregroundColor(.white.opacity(0.2))
                    Text("No exchanges yet")
                        .font(.system(size: 13, design: .monospaced))
                        .foregroundColor(.white.opacity(0.45))
                    Text("Build a request on the left and hit Send. Out-of-scope URLs are rejected before any I/O.")
                        .font(.system(size: 11))
                        .foregroundColor(.white.opacity(0.35))
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 24)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
    }
}


// MARK: - View model

@MainActor
final class VerifyConsoleViewModel: ObservableObject {
    @Published var sessions: [VerifySessionSummary] = []
    @Published var selectedSessionId: String? = nil
    @Published var session: VerifySession?

    @Published var requestMethod: String = "GET"
    @Published var requestURL: String = ""
    @Published var requestHeadersRaw: String = ""
    @Published var requestBody: String = ""

    @Published var selectedExchangeIndices: Set<Int> = []
    @Published var isSending: Bool = false
    @Published var errorMessage: String?

    @Published var promoteResult: VerifyPromoteResult?

    @Published var scopeAlertVisible: Bool = false
    @Published var scopeAlertMessage: String = ""
    private var pendingScopeURL: String?

    private let client = VerifyAPIClient.shared
    private var pollTask: Task<Void, Never>?

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
            sessions = try await client.listSessions()
            // Auto-select first session if none chosen.
            if selectedSessionId == nil, let first = sessions.first {
                selectedSessionId = first.sessionId
            }
            if let id = selectedSessionId {
                session = try await client.getSession(id)
            }
        } catch {
            errorMessage = "Refresh: \(error.localizedDescription)"
        }
    }

    // MARK: actions

    func openNewSessionSheet() async {
        // Minimal create — target_url manual input via a popover would
        // be nicer; for now, fall back to a clipboard pull as the
        // ad-hoc entrypoint (matches operator habit).
        let pasteboard = NSPasteboard.general
        let raw = pasteboard.string(forType: .string) ?? ""
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.hasPrefix("http") else {
            errorMessage = "To create a session, copy a target URL to the clipboard first (or use a finding-bound session)."
            return
        }
        do {
            let r = try await client.createSession(targetUrl: trimmed)
            selectedSessionId = r.sessionId
            await refresh()
            errorMessage = nil
        } catch {
            errorMessage = "Create: \(error.localizedDescription)"
        }
    }

    func openAddScopeSheet() async {
        // Quick path: pull from clipboard. Same operator-habit hook.
        let raw = NSPasteboard.general.string(forType: .string) ?? ""
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, let id = selectedSessionId else { return }
        do {
            let r = try await client.addScope(sessionId: id, urlOrOrigin: trimmed)
            if r.added {
                await refresh()
                errorMessage = "Scope expanded: \(r.allowedOrigins.joined(separator: ", "))"
            } else {
                errorMessage = "Already in scope."
            }
        } catch {
            errorMessage = "Add scope: \(error.localizedDescription)"
        }
    }

    func confirmAddRejectedToScope() async {
        guard let url = pendingScopeURL, let id = selectedSessionId else { return }
        do {
            _ = try await client.addScope(sessionId: id, urlOrOrigin: url)
            await refresh()
            pendingScopeURL = nil
            // Retry the request now that scope includes it.
            await sendRequest()
        } catch {
            errorMessage = "Add scope: \(error.localizedDescription)"
        }
    }

    func sendRequest() async {
        guard let id = selectedSessionId, !requestURL.isEmpty else { return }
        isSending = true
        defer { isSending = false }
        errorMessage = nil
        let headers = parseHeaders(requestHeadersRaw)
        let bodyArg = requestBody.isEmpty ? nil : requestBody
        do {
            _ = try await client.sendExchange(
                sessionId: id,
                method: requestMethod,
                url: requestURL,
                headers: headers,
                body: bodyArg
            )
            await refresh()
        } catch let e as VerifyAPIError {
            switch e {
            case .httpError(403, _, let badURL?, let origins?):
                // Out-of-scope: prompt operator to add and retry.
                pendingScopeURL = badURL
                scopeAlertMessage = "URL `\(badURL)` is not in scope. Current allowlist: \(origins.joined(separator: ", "))"
                scopeAlertVisible = true
            default:
                errorMessage = e.localizedDescription
            }
        } catch {
            errorMessage = "Send: \(error.localizedDescription)"
        }
    }

    func promoteSelected() async {
        guard let id = selectedSessionId, !selectedExchangeIndices.isEmpty else { return }
        do {
            let result = try await client.promote(
                sessionId: id,
                exchangeIndices: Array(selectedExchangeIndices).sorted(),
                sanitize: true
            )
            promoteResult = result
        } catch {
            errorMessage = "Promote: \(error.localizedDescription)"
        }
    }

    private func parseHeaders(_ raw: String) -> [String: String] {
        var out: [String: String] = [:]
        for line in raw.split(separator: "\n") {
            let parts = line.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2 else { continue }
            let k = parts[0].trimmingCharacters(in: .whitespaces)
            let v = parts[1].trimmingCharacters(in: .whitespaces)
            if !k.isEmpty { out[k] = v }
        }
        return out
    }
}


// MARK: - ExchangeRow

private struct ExchangeRow: View {
    let index: Int
    let exchange: VerifyExchange
    let isSelected: Bool
    let onToggle: () -> Void

    @State private var expanded: Bool = false

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 10) {
                Button(action: onToggle) {
                    Image(systemName: isSelected ? "checkmark.square.fill" : "square")
                        .foregroundColor(isSelected ? .cyberCyan : .white.opacity(0.4))
                        .font(.system(size: 14))
                }.buttonStyle(.plain)

                Text("[\(index)]")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(.white.opacity(0.5))

                Text(exchange.method)
                    .font(.system(size: 11, weight: .bold, design: .monospaced))
                    .foregroundColor(.cyberCyan)
                    .frame(width: 50, alignment: .leading)

                Text(exchange.url)
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundColor(.white.opacity(0.9))
                    .lineLimit(1)

                Spacer()

                statusPill(exchange.responseStatus)

                Button { withAnimation(.easeInOut(duration: 0.15)) { expanded.toggle() } } label: {
                    Image(systemName: expanded ? "chevron.up" : "chevron.down")
                        .foregroundColor(.white.opacity(0.5))
                }.buttonStyle(.plain)
            }

            if expanded {
                VStack(alignment: .leading, spacing: 6) {
                    if !exchange.requestBody.isEmpty {
                        Text("Request body")
                            .font(.system(size: 10, weight: .bold, design: .monospaced))
                            .foregroundColor(.white.opacity(0.55))
                        Text(exchange.requestBody)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(.white.opacity(0.85))
                            .padding(8)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color.black.opacity(0.4))
                            .cornerRadius(4)
                    }
                    Text("Response body (HTTP \(exchange.responseStatus), \(Int(exchange.responseElapsedMs))ms)")
                        .font(.system(size: 10, weight: .bold, design: .monospaced))
                        .foregroundColor(.white.opacity(0.55))
                    Text(exchange.responseBody.isEmpty ? "(empty)" : exchange.responseBody)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.white.opacity(0.85))
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color.black.opacity(0.4))
                        .cornerRadius(4)
                }
                .padding(.leading, 32)
            }
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

    private func statusPill(_ status: Int) -> some View {
        let color: Color = {
            switch status {
            case 0:        return .red
            case 200..<300: return .green
            case 300..<400: return .yellow
            case 400..<500: return .orange
            case 500..<600: return .red
            default:       return .gray
            }
        }()
        return Text("\(status)")
            .font(.system(size: 11, weight: .bold, design: .monospaced))
            .foregroundColor(color)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.15))
            .cornerRadius(4)
    }
}


// MARK: - Promote sheet

private struct PromoteResultSheet: View {
    let result: VerifyPromoteResult
    let onClose: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Promote to Repro")
                        .font(.system(size: 18, weight: .bold, design: .monospaced))
                        .foregroundColor(.cyberCyan)
                    Text("\(result.entryCount) entry(s) · target \(result.targetUrl)")
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundColor(.white.opacity(0.65))
                }
                Spacer()
                Button("Copy all") {
                    let joined = result.entries.enumerated().map { (i, e) in
                        "\(i + 1). \(e.markdown)"
                    }.joined(separator: "\n\n")
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(joined, forType: .string)
                }
                Button("Close") { onClose() }
            }
            .padding()

            Divider()

            if !result.placeholderLegend.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Substitute before running:")
                        .font(.system(size: 10, weight: .bold, design: .monospaced))
                        .foregroundColor(.white.opacity(0.65))
                    ForEach(result.placeholderLegend.sorted(by: { $0.key < $1.key }), id: \.key) { kv in
                        Text("  \(kv.key) = \(kv.value)")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(.white.opacity(0.85))
                    }
                }
                .padding()
                .background(Color.yellow.opacity(0.08))
            }

            ScrollView {
                LazyVStack(alignment: .leading, spacing: 12) {
                    ForEach(result.entries) { entry in
                        VStack(alignment: .leading, spacing: 8) {
                            Text("\(entry.index). \(entry.prose)")
                                .font(.system(size: 13, design: .monospaced))
                                .foregroundColor(.white)
                            Text(entry.curl)
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundColor(.green.opacity(0.85))
                                .padding(8)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(Color.black.opacity(0.45))
                                .cornerRadius(4)
                            if entry.responseStatus > 0 {
                                Text("Response (HTTP \(entry.responseStatus))")
                                    .font(.system(size: 10, weight: .bold, design: .monospaced))
                                    .foregroundColor(.white.opacity(0.5))
                                Text(entry.responseExcerpt)
                                    .font(.system(size: 11, design: .monospaced))
                                    .foregroundColor(.white.opacity(0.85))
                                    .padding(8)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .background(Color.black.opacity(0.4))
                                    .cornerRadius(4)
                            }
                        }
                        .padding(12)
                        .background(Color.white.opacity(0.04))
                        .cornerRadius(6)
                    }
                }
                .padding(16)
            }
        }
        .frame(minWidth: 800, minHeight: 600)
        .background(Color(red: 0.05, green: 0.05, blue: 0.08))
        .foregroundColor(.white)
    }
}
