//
//  BolaLabView.swift
//  SentinelForgeUI
//

import SwiftUI
import AppKit

@MainActor
final class BolaLabViewModel: ObservableObject {
    @Published var targetUrl: String = "https://biz.yelp.com/"
    
    @Published var personas: [FoundryPersona] = []
    @Published var envelopes: [FoundryAuthorizationEnvelope] = []
    @Published var selectedEnvelopeId: String = ""
    @Published var actorStatuses: [String: String] = [:]
    @Published var isCapturing: [String: Bool] = [:]
    @Published var captureFiles: [String: String] = [:]
    @Published var openPersonaWindowIds: Set<String> = []
    @Published var behavioralStatus: String =
        "Open and authenticate two persona windows, then capture both and run."
    @Published var isRunningBehavioral = false
    
    private let baseURL = "http://127.0.0.1:8765/v1/driver"

    private static func readAPIToken() -> String? {
        let path = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".sentinelforge", isDirectory: true)
            .appendingPathComponent("api_token")
        return try? String(contentsOf: path, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func driverRequest(path: String, method: String) -> URLRequest? {
        guard let endpoint = URL(string: "\(baseURL)/\(path)") else { return nil }
        var request = URLRequest(url: endpoint)
        request.httpMethod = method
        if let token = Self.readAPIToken(), !token.isEmpty {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        return request
    }
    
    func fetchPersonas() async {
        do {
            let fetched = try await FoundryAPIClient.shared.listPersonas()
            self.personas = fetched
            for p in fetched {
                if actorStatuses[p.personaId] == nil {
                    actorStatuses[p.personaId] = "Idle"
                    isCapturing[p.personaId] = false
                }
            }
            let fetchedEnvelopes = try await FoundryAPIClient.shared.listAuthorizationEnvelopes()
            self.envelopes = fetchedEnvelopes.filter {
                $0.isApproved && $0.allowedWorkflows.contains("behavioral_object_authorization")
            }
            if selectedEnvelopeId.isEmpty {
                selectedEnvelopeId = envelopes.first?.envelopeId ?? ""
            }
        } catch {
            print("BolaLabViewModel failed to fetch personas: \(error)")
        }
    }

    var isAnyCaptureActive: Bool {
        isCapturing.values.contains(true)
    }

    var canRunBehavioral: Bool {
        !selectedEnvelopeId.isEmpty
            && personas.filter { captureFiles[$0.personaId] != nil }.count >= 2
            && !isAnyCaptureActive
            && !isRunningBehavioral
    }

    private var openPersonaWindows: [FoundryPersona] {
        personas.filter {
            openPersonaWindowIds.contains($0.personaId)
                && DriverBridgeClient.shared.personaWindows[$0.personaId] != nil
        }
    }

    var canRunOneClick: Bool {
        guard let url = URL(string: targetUrl),
              let scheme = url.scheme?.lowercased(),
              ["http", "https"].contains(scheme),
              url.host != nil else { return false }
        return !selectedEnvelopeId.isEmpty
            && openPersonaWindows.count >= 2
            && !isAnyCaptureActive
            && !isRunningBehavioral
    }

    func personaWindowDidOpen(for persona: FoundryPersona) {
        openPersonaWindowIds.insert(persona.personaId)
        actorStatuses[persona.personaId] = "Window open — authenticate and leave it open."
    }

    func personaWindowDidClose(for persona: FoundryPersona) {
        openPersonaWindowIds.remove(persona.personaId)
        actorStatuses[persona.personaId] = "Window closed."
    }
    
    func startCapture(for persona: FoundryPersona) {
        Task {
            await executeStartCapture(url: targetUrl, persona: persona)
        }
    }
    
    private func executeStartCapture(url: String, persona: FoundryPersona) async {
        captureFiles.removeValue(forKey: persona.personaId)
        isCapturing[persona.personaId] = true
        actorStatuses[persona.personaId] = "Starting secure capture..."
        
        do {
            guard var request = driverRequest(path: "start_capture", method: "POST") else {
                throw NSError(
                    domain: "BolaLab",
                    code: 400,
                    userInfo: [NSLocalizedDescriptionKey: "Invalid driver endpoint"]
                )
            }
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            
            let payload: [String: Any] = [
                "url": url,
                "persona_id": persona.personaId,
            ]
            request.httpBody = try JSONSerialization.data(withJSONObject: payload)
            
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let http = response as? HTTPURLResponse,
                  (200...299).contains(http.statusCode) else {
                throw NSError(
                    domain: "BolaLab",
                    code: (response as? HTTPURLResponse)?.statusCode ?? 500,
                    userInfo: [
                        NSLocalizedDescriptionKey:
                            String(data: data, encoding: .utf8) ?? "Capture start failed"
                    ]
                )
            }
            
            guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  json["status"] as? String == "ok",
                  let captureFile = json["capture_file"] as? String,
                  !captureFile.isEmpty else {
                throw NSError(
                    domain: "BolaLab",
                    code: 500,
                    userInfo: [NSLocalizedDescriptionKey: "Driver omitted capture path"]
                )
            }
            captureFiles[persona.personaId] = captureFile
            actorStatuses[persona.personaId] = "Capturing as \(persona.label)..."
        } catch {
            actorStatuses[persona.personaId] = "Error: \(error.localizedDescription)"
            isCapturing[persona.personaId] = false
        }
    }
    
    func stopCapture(for persona: FoundryPersona) {
        Task {
            do {
                guard let request = driverRequest(path: "stop_capture", method: "POST") else {
                    throw NSError(
                        domain: "BolaLab",
                        code: 400,
                        userInfo: [NSLocalizedDescriptionKey: "Invalid driver endpoint"]
                    )
                }
                
                let (data, response) = try await URLSession.shared.data(for: request)
                guard let http = response as? HTTPURLResponse,
                      (200...299).contains(http.statusCode) else {
                    throw NSError(
                        domain: "BolaLab",
                        code: (response as? HTTPURLResponse)?.statusCode ?? 500,
                        userInfo: [
                            NSLocalizedDescriptionKey:
                                String(data: data, encoding: .utf8) ?? "Capture stop failed"
                        ]
                    )
                }
                
                if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   json["limit_reached"] as? Bool == true {
                    let records = json["records"] as? Int ?? 0
                    actorStatuses[persona.personaId] =
                        "Saved at capture safety limit (\(records) records)."
                } else {
                    actorStatuses[persona.personaId] = "Saved."
                }
                isCapturing[persona.personaId] = false
            } catch {
                actorStatuses[persona.personaId] = "Stop Error: \(error.localizedDescription)"
                isCapturing[persona.personaId] = false
            }
        }
    }

    func runBehavioralAuthorization() {
        Task {
            let captured = personas.filter { captureFiles[$0.personaId] != nil }
            guard captured.count >= 2 else {
                behavioralStatus = "Two completed persona captures are required."
                return
            }
            guard !selectedEnvelopeId.isEmpty else {
                behavioralStatus = "Select an approved authorization envelope."
                return
            }
            let source = captured[0]
            let peer = captured[1]
            guard let sourcePath = captureFiles[source.personaId],
                  let peerPath = captureFiles[peer.personaId] else { return }

            isRunningBehavioral = true
            behavioralStatus = "Behavioral planner is evaluating the paired captures..."
            defer { isRunningBehavioral = false }
            do {
                let sourceRecords = try loadCapture(path: sourcePath)
                let peerRecords = try loadCapture(path: peerPath)
                let scriptURLs: [String]
                if let sourceWindow = DriverBridgeClient.shared.personaWindows[source.personaId] {
                    scriptURLs = (try? await sourceWindow.scriptResourceURLs()) ?? []
                } else {
                    scriptURLs = []
                }
                let result = try await FoundryAPIClient.shared.runBehavioralAuthorization(
                    targetOrigin: targetUrl,
                    envelopeId: selectedEnvelopeId,
                    sourcePersonaId: source.personaId,
                    peerPersonaId: peer.personaId,
                    sourceRecords: sourceRecords,
                    peerRecords: peerRecords,
                    scriptURLs: scriptURLs
                )
                if let verdict = result.execution?.legacyVerdict {
                    behavioralStatus = "\(result.status): legacy verdict \(verdict)"
                } else if let proposal = result.plan.selectedProposalId {
                    behavioralStatus = "Plan ready: \(proposal.prefix(16))… (active execution is off)"
                } else {
                    behavioralStatus = "\(result.status): no executable read candidate"
                }
            } catch {
                behavioralStatus = "Behavioral run failed: \(error.localizedDescription)"
            }
        }
    }

    func runBehavioralAuthorizationFromURL() {
        Task {
            let windowed = openPersonaWindows
            guard windowed.count >= 2 else {
                behavioralStatus = "Two open, authenticated persona windows are required."
                return
            }
            guard !selectedEnvelopeId.isEmpty else {
                behavioralStatus = "Select an approved authorization envelope."
                return
            }
            let source = windowed[0]
            let peer = windowed[1]

            isRunningBehavioral = true
            behavioralStatus =
                "Capturing \(source.label), then \(peer.label), then running one proof..."
            defer { isRunningBehavioral = false }
            do {
                let result = try await FoundryAPIClient.shared
                    .runBehavioralAuthorizationFromURL(
                        targetURL: targetUrl,
                        envelopeId: selectedEnvelopeId,
                        sourcePersonaId: source.personaId,
                        peerPersonaId: peer.personaId
                    )
                if result.status == "already_executed" {
                    actorStatuses[source.personaId] = "Prior automatic capture reused."
                    actorStatuses[peer.personaId] = "Prior automatic capture reused."
                    behavioralStatus = "Identical one-click run already completed."
                } else if let verdict = result.execution?.legacyVerdict {
                    actorStatuses[source.personaId] = "Automatic capture complete."
                    actorStatuses[peer.personaId] = "Automatic capture complete."
                    if let exploration = result.readExploration,
                       exploration.selectedAfterPair > 0 {
                        behavioralStatus =
                            "Discovered after \(exploration.pairsCompleted) paired read(s): "
                            + "legacy verdict \(verdict)"
                    } else {
                        behavioralStatus = "\(result.status): legacy verdict \(verdict)"
                    }
                } else {
                    actorStatuses[source.personaId] = "Automatic capture complete."
                    actorStatuses[peer.personaId] = "Automatic capture complete."
                    behavioralStatus = "\(result.status): no executable read candidate"
                }
            } catch {
                behavioralStatus = "One-click run failed: \(error.localizedDescription)"
            }
        }
    }

    private func loadCapture(path: String) throws -> [[String: Any]] {
        let text = try String(contentsOfFile: path, encoding: .utf8)
        var records: [[String: Any]] = []
        for line in text.split(whereSeparator: \.isNewline) {
            guard let data = String(line).data(using: .utf8),
                  let record = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                throw NSError(
                    domain: "BolaLab",
                    code: 400,
                    userInfo: [NSLocalizedDescriptionKey: "Capture contains malformed JSONL"]
                )
            }
            records.append(record)
            if records.count > 20_000 {
                throw NSError(
                    domain: "BolaLab",
                    code: 413,
                    userInfo: [NSLocalizedDescriptionKey: "Capture exceeds 20,000 records"]
                )
            }
        }
        if records.isEmpty {
            throw NSError(
                domain: "BolaLab",
                code: 422,
                userInfo: [NSLocalizedDescriptionKey: "Capture is empty"]
            )
        }
        return records
    }
}

struct BolaLabView: View {
    @StateObject private var vm = BolaLabViewModel()
    let panelColors: [Color] = [.purple, .orange, .green, .blue, .red, .pink, .yellow]
    
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("BOLA Capture Lab")
                .font(.system(size: 28, weight: .bold, design: .monospaced))
                .foregroundColor(.cyberCyan)
            
            Text("Capture session data for Broken Object Level Authorization testing.")
                .font(.system(size: 14, design: .monospaced))
                .foregroundColor(.white.opacity(0.7))
            
            Divider()
            
            VStack(alignment: .leading, spacing: 8) {
                Text("Target URL")
                    .font(.system(size: 12, weight: .bold, design: .monospaced))
                    .foregroundColor(.white.opacity(0.5))
                TextField("https://...", text: $vm.targetUrl)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .font(.system(size: 14, design: .monospaced))
            }
            .padding(.bottom, 10)

            HStack(spacing: 12) {
                Picker("Authorization", selection: $vm.selectedEnvelopeId) {
                    if vm.envelopes.isEmpty {
                        Text("No approved behavioral envelope").tag("")
                    }
                    ForEach(vm.envelopes) { envelope in
                        Text(envelope.targetHandle).tag(envelope.envelopeId)
                    }
                }
                .frame(maxWidth: 360)

                VStack(alignment: .trailing, spacing: 8) {
                    Button {
                        vm.runBehavioralAuthorizationFromURL()
                    } label: {
                        Label(
                            vm.isRunningBehavioral ? "Running..." : "Capture Both & Run",
                            systemImage: "bolt.shield.fill"
                        )
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.cyberCyan)
                    .disabled(!vm.canRunOneClick)

                    Button("Run Saved Captures") {
                        vm.runBehavioralAuthorization()
                    }
                    .buttonStyle(.bordered)
                    .disabled(!vm.canRunBehavioral)
                }
            }

            Text(vm.behavioralStatus)
                .font(.system(size: 12, design: .monospaced))
                .foregroundColor(.white.opacity(0.7))
            
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 30) {
                    ForEach(Array(vm.personas.enumerated()), id: \.element.personaId) { index, persona in
                        actorPanel(
                            name: persona.label,
                            status: vm.actorStatuses[persona.personaId] ?? "Idle",
                            isCapturing: vm.isCapturing[persona.personaId] ?? false,
                            captureBlocked: vm.isRunningBehavioral || vm.isAnyCaptureActive
                                && !(vm.isCapturing[persona.personaId] ?? false),
                            color: panelColors[index % panelColors.count]
                        ) {
                            vm.startCapture(for: persona)
                        } onStop: {
                            vm.stopCapture(for: persona)
                        } onOpenWindow: {
                            if let existing = DriverBridgeClient.shared
                                .personaWindows[persona.personaId] {
                                existing.makeKeyAndOrderFront(nil)
                                vm.personaWindowDidOpen(for: persona)
                                return
                            }
                            let window = GhostBrowserWindow(
                                contentRect: NSRect(x: 100, y: 100, width: 1024, height: 768),
                                styleMask: [.titled, .closable, .miniaturizable, .resizable],
                                backing: .buffered,
                                defer: false
                            )
                            window.title = "SND Window - \(persona.label)"
                            
                            let wc = NSWindowController(window: window)
                            wc.showWindow(nil)
                            window.makeKeyAndOrderFront(nil)
                            
                            // The backend addresses owned personas by immutable vault ID.
                            // Keep the label alias for older replay callers.
                            DriverBridgeClient.shared.personaWindows[persona.personaId] = window
                            DriverBridgeClient.shared.personaWindows[persona.label] = window
                            vm.personaWindowDidOpen(for: persona)
                            window.onClose = { [weak window] in
                                guard let window else { return }
                                let windows = DriverBridgeClient.shared.personaWindows
                                var removedPersonaWindow = false
                                if windows[persona.personaId] === window {
                                    DriverBridgeClient.shared.personaWindows.removeValue(
                                        forKey: persona.personaId
                                    )
                                    removedPersonaWindow = true
                                }
                                if windows[persona.label] === window {
                                    DriverBridgeClient.shared.personaWindows.removeValue(
                                        forKey: persona.label
                                    )
                                }
                                if removedPersonaWindow {
                                    vm.personaWindowDidClose(for: persona)
                                }
                            }
                            
                            Task {
                                try? await window.navigate(url: vm.targetUrl)
                            }
                        }
                    }
                    
                    if vm.personas.isEmpty {
                        Text("No personas found in the Foundry. Please add them first.")
                            .font(.system(size: 14, design: .monospaced))
                            .foregroundColor(.white.opacity(0.5))
                            .padding()
                    }
                }
            }
            
            Spacer()
        }
        .padding(30)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .task {
            await vm.fetchPersonas()
        }
    }
    
    private func actorPanel(name: String, status: String, isCapturing: Bool, captureBlocked: Bool, color: Color, onStart: @escaping () -> Void, onStop: @escaping () -> Void, onOpenWindow: @escaping () -> Void) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("\(name) (Attacker/Victim)")
                .font(.system(size: 18, weight: .bold, design: .monospaced))
                .foregroundColor(color)
            
            Text("Status: \(status)")
                .font(.system(size: 12, design: .monospaced))
                .foregroundColor(.white.opacity(0.8))
                .lineLimit(2)
            
            HStack {
                Button(action: onOpenWindow) {
                    Label("Window", systemImage: "macwindow")
                }
                .buttonStyle(.bordered)
                
                Button(action: onStart) {
                    Label("Capture \(name)", systemImage: "record.circle")
                }
                .buttonStyle(.borderedProminent)
                .tint(color.opacity(0.8))
                .disabled(isCapturing || captureBlocked)
                
                if status.contains("Capturing") {
                    Button(action: onStop) {
                        Label("Stop & Save", systemImage: "stop.fill")
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.red)
                }
            }
        }
        .padding()
        .frame(width: 300)
        .background(Color.white.opacity(0.05))
        .cornerRadius(10)
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(color.opacity(0.3), lineWidth: 1))
    }
}
