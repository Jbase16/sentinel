//
//  FoundryConsoleView.swift
//  SentinelForgeUI — Phase 7-PF10
//
//  The operator-facing surface for the Persona Foundry. The hero of
//  this view is the CHALLENGE HANDOFF strip at the top: when a signup
//  hits an anti-bot wall, a "Sentinel needs you" card appears with the
//  page screenshot, the prompt, and a one-click resolve. That single
//  click is the whole innovation — the human spends one second on the
//  rare-but-hard step instead of thirty minutes on the whole signup.
//
//  Layout:
//    * Top — challenge handoff cards (only shown when challenges are
//            pending). The "Sentinel needs you" surface.
//    * Below — three panels:
//        - Account Plan (enter target + vuln classes → topology)
//        - Personas + Recipes (what's in the vault / recipe store)
//        - Signup Jobs (running / completed)
//
//  Polls /challenges + /signup every 2s while visible so the handoff
//  surfaces fast (a human solving a CAPTCHA won't notice a 2s delay).
//

import SwiftUI

public struct FoundryConsoleView: View {
    @StateObject private var vm = FoundryConsoleViewModel()
    @State private var showAddPersona = false
    @State private var showAddEnvelope = false
    @State private var showRecordRecipe = false

    public init() {}

    public var body: some View {
        VStack(spacing: 0) {
            header

            // The hero: pending challenges. Only appears when there's a
            // handoff waiting.
            if !vm.challenges.isEmpty {
                challengeStrip
                    .transition(.move(edge: .top).combined(with: .opacity))
            }

            Divider()

            HStack(spacing: 0) {
                planPane
                    .frame(width: 340)
                    .background(Color.black.opacity(0.25))
                Divider()
                vaultPane
                    .frame(maxWidth: .infinity)
            }
        }
        .foregroundColor(.white)
        .onAppear { vm.start() }
        .onDisappear { vm.stop() }
        .sheet(isPresented: $showAddPersona) {
            AddPersonaSheet(onSaved: { Task { await vm.refresh() } })
        }
        .sheet(isPresented: $showAddEnvelope) {
            AddAuthorizationEnvelopeSheet(
                onSave: { draft in
                    Task { await vm.createEnvelope(draft) }
                }
            )
        }
        .sheet(isPresented: $showRecordRecipe) {
            RecordRecipeSheet(
                isRecording: $vm.isRecording,
                onRecord: { handle, name, origin in
                    Task { await vm.recordRecipe(serviceHandle: handle, name: name, origin: origin) }
                }
            )
        }
    }

    // MARK: header

    private var header: some View {
        HStack(spacing: 14) {
            Image(systemName: "person.badge.key.fill")
                .foregroundColor(.cyberCyan)
                .font(.system(size: 16))
            Text("PERSONA FOUNDRY")
                .font(.system(size: 14, weight: .bold, design: .monospaced))
                .foregroundColor(.cyberCyan)
            if !vm.challenges.isEmpty {
                Text("· \(vm.challenges.count) handoff(s) waiting")
                    .font(.system(size: 12, weight: .bold, design: .monospaced))
                    .foregroundColor(.orange)
            }
            Spacer()
            Button { Task { await vm.refresh() } } label: {
                Image(systemName: "arrow.clockwise")
            }.buttonStyle(.plain)
            if let err = vm.errorMessage {
                Text(err).font(.system(size: 11, design: .monospaced)).foregroundColor(.red)
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .background(Color.black.opacity(0.4))
    }

    // MARK: challenge strip (the hero)

    private var challengeStrip: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("🔔 SENTINEL NEEDS YOU")
                .font(.system(size: 12, weight: .black, design: .monospaced))
                .foregroundColor(.orange)
                .padding(.horizontal, 16)
                .padding(.top, 10)
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 12) {
                    ForEach(vm.challenges) { ch in
                        ChallengeCard(
                            challenge: ch,
                            valueDraft: vm.bindingValueDraft(ch.challengeId),
                            onValueChange: { vm.setValueDraft(ch.challengeId, $0) },
                            onResolve: { Task { await vm.resolve(ch, resolved: true) } },
                            onDecline: { Task { await vm.resolve(ch, resolved: false) } }
                        )
                    }
                }
                .padding(.horizontal, 16)
                .padding(.bottom, 12)
            }
        }
        .background(Color.orange.opacity(0.08))
    }

    // MARK: plan pane

    private var planPane: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("ACCOUNT PLAN")
                .font(.system(size: 11, weight: .bold, design: .monospaced))
                .foregroundColor(.white.opacity(0.65))
                .padding(.top, 12).padding(.horizontal, 16)

            VStack(alignment: .leading, spacing: 8) {
                TextField("target handle (e.g. airtable)", text: $vm.planTarget)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 12, design: .monospaced))
                Text("Vuln classes to test (toggle):")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(.white.opacity(0.5))
                ForEach(vm.availableVulnClasses, id: \.self) { vc in
                    Toggle(isOn: vm.vulnBinding(vc)) {
                        Text(vc).font(.system(size: 11, design: .monospaced))
                    }
                    .toggleStyle(.checkbox)
                }
                Button { Task { await vm.computePlan() } } label: {
                    Label("Compute Plan", systemImage: "rectangle.3.group")
                }
                .buttonStyle(.borderedProminent)
                .tint(.purple)
                .disabled(vm.planTarget.isEmpty || vm.selectedVulnClasses.isEmpty)
            }
            .padding(.horizontal, 16)

            if let plan = vm.plan {
                Divider()
                ScrollView {
                    VStack(alignment: .leading, spacing: 8) {
                        Text(plan.summary)
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundColor(.cyberCyan)
                            .fixedSize(horizontal: false, vertical: true)
                        ForEach(plan.accounts) { acct in
                            VStack(alignment: .leading, spacing: 3) {
                                Text("\(acct.label) — \(acct.role)")
                                    .font(.system(size: 12, weight: .bold, design: .monospaced))
                                Text("tenant: \(acct.tenantGroup)")
                                    .font(.system(size: 10, design: .monospaced))
                                    .foregroundColor(.white.opacity(0.5))
                                if let fp = acct.fingerprint {
                                    Text("plant: \(fp)")
                                        .font(.system(size: 10, design: .monospaced))
                                        .foregroundColor(.green)
                                }
                                ForEach(acct.setupActions, id: \.self) { a in
                                    Text("• \(a)")
                                        .font(.system(size: 10))
                                        .foregroundColor(.white.opacity(0.7))
                                        .fixedSize(horizontal: false, vertical: true)
                                }
                            }
                            .padding(8)
                            .background(Color.white.opacity(0.04))
                            .cornerRadius(6)
                        }
                    }
                    .padding(.horizontal, 16)
                }
            }
            Spacer()
        }
    }

    // MARK: vault pane

    private var vaultPane: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("VAULT & JOBS")
                    .font(.system(size: 11, weight: .bold, design: .monospaced))
                    .foregroundColor(.white.opacity(0.65))
                Spacer()
                Button(action: { showAddPersona = true }) {
                    HStack(spacing: 4) {
                        Image(systemName: "person.badge.plus")
                        Text("New Persona")
                    }
                }
                .buttonStyle(.plain)
                .help("Create a new persona in the Foundry vault")
                Button(action: { showAddEnvelope = true }) {
                    HStack(spacing: 4) {
                        Image(systemName: "checkmark.shield")
                        Text("New Envelope")
                    }
                }
                .buttonStyle(.plain)
                .help("Declare the authorization that gates Foundry execution")
            }
            .padding(.horizontal, 16).padding(.vertical, 10)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    section("AUTHORIZATION (\(vm.envelopes.count))") {
                        if vm.envelopes.isEmpty {
                            emptyHint("Create an authorization envelope before replaying a recipe.")
                        } else {
                            Picker(
                                "Execution envelope",
                                selection: $vm.selectedEnvelopeId
                            ) {
                                Text("Select an envelope").tag("")
                                ForEach(vm.envelopes) { envelope in
                                    Text(vm.envelopeLabel(envelope))
                                        .tag(envelope.envelopeId)
                                }
                            }
                            .pickerStyle(.menu)

                            if let envelope = vm.selectedEnvelope {
                                HStack(spacing: 6) {
                                    Circle()
                                        .fill(envelope.isApproved && !envelope.isExpired ? Color.green : Color.red)
                                        .frame(width: 7, height: 7)
                                    Text(envelope.isApproved && !envelope.isExpired ? "APPROVED" : "NOT EXECUTABLE")
                                        .font(.system(size: 10, weight: .bold, design: .monospaced))
                                    Text(envelope.authorizedOrigins.joined(separator: ", "))
                                        .font(.system(size: 10, design: .monospaced))
                                        .foregroundColor(.white.opacity(0.55))
                                        .lineLimit(1)
                                    Spacer()
                                }
                            }
                        }
                    }
                    section("PERSONAS (\(vm.personas.count))") {
                        ForEach(vm.personas) { p in
                            HStack {
                                Image(systemName: "person.fill").foregroundColor(.cyberCyan)
                                    .font(.system(size: 11))
                                Text(p.label).font(.system(size: 12, design: .monospaced))
                                Text(p.email).font(.system(size: 11, design: .monospaced))
                                    .foregroundColor(.white.opacity(0.55))
                                Spacer()
                            }
                        }
                        if vm.personas.isEmpty { emptyHint("Add a research persona via the API to get started.") }
                    }
                    section("RECIPES (\(vm.recipes.count))") {
                        ForEach(vm.recipes) { r in
                            HStack {
                                Image(systemName: "doc.plaintext").foregroundColor(.white.opacity(0.6))
                                    .font(.system(size: 11))
                                Text("\(r.name) [\(r.serviceHandle)]")
                                    .font(.system(size: 12, design: .monospaced))
                                Text("\(r.stepCount) steps · \(r.challengeCount) walls")
                                    .font(.system(size: 10, design: .monospaced))
                                    .foregroundColor(.white.opacity(0.5))
                                Spacer()
                                Menu("Run") {
                                    ForEach(vm.personas, id: \.personaId) { p in
                                        Button(p.label) {
                                            Task {
                                                await vm.startSignup(
                                                    recipe: r,
                                                    personaId: p.personaId
                                                )
                                            }
                                        }
                                    }
                                }
                                .buttonStyle(.bordered).controlSize(.small)
                                .disabled(
                                    vm.personas.isEmpty
                                        || vm.selectedExecutableEnvelope(for: r) == nil
                                )
                                .help(vm.signupRunHelp(for: r))
                                Button(role: .destructive, action: { Task { await vm.deleteRecipe(recipeId: r.recipeId) } }) {
                                    Image(systemName: "trash")
                                }
                                .buttonStyle(.borderless)
                                .foregroundColor(.red.opacity(0.8))
                            }
                        }
                        if vm.recipes.isEmpty { emptyHint("Record a signup (PF8) or hand-author a recipe.") }
                        
                        Button(action: { showRecordRecipe = true }) {
                            HStack(spacing: 4) {
                                Image(systemName: "record.circle")
                                Text(vm.isRecording ? "Recording in progress..." : "Record Recipe")
                            }
                        }
                        .buttonStyle(.plain)
                        .foregroundColor(vm.isRecording ? .red : .cyberCyan)
                        .disabled(vm.isRecording)
                    }
                    section("SIGNUP JOBS (\(vm.jobs.count))") {
                        ForEach(vm.jobs) { j in
                            HStack {
                                jobStatePill(j.state)
                                Text(j.serviceHandle).font(.system(size: 12, design: .monospaced))
                                if let e = j.error {
                                    Text(e).font(.system(size: 10, design: .monospaced)).foregroundColor(.red).lineLimit(1)
                                }
                                Spacer()
                            }
                        }
                        if vm.jobs.isEmpty { emptyHint("No signup jobs yet.") }
                    }
                }
                .padding(16)
            }
        }
    }

    private func section<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.system(size: 10, weight: .bold, design: .monospaced))
                .foregroundColor(.white.opacity(0.5))
            content()
        }
    }

    private func emptyHint(_ s: String) -> some View {
        Text(s).font(.system(size: 11)).foregroundColor(.white.opacity(0.35))
    }

    private func jobStatePill(_ state: String) -> some View {
        let color: Color = {
            switch state {
            case "completed": return .green
            case "running", "pending": return .cyan
            case "aborted": return .yellow
            case "failed": return .red
            default: return .gray
            }
        }()
        return Text(state)
            .font(.system(size: 10, weight: .bold, design: .monospaced))
            .foregroundColor(color)
            .padding(.horizontal, 6).padding(.vertical, 2)
            .background(color.opacity(0.15)).cornerRadius(4)
    }
}

private struct AuthorizationEnvelopeDraft {
    let researcherIdentity: String
    let targetHandle: String
    let authorizedOrigins: [String]
    let authorizationBasis: String
    let allowedWorkflows: [String]
    let disclosureAttestation: Bool
    let maxAccountsPerService: Int
    let legalPosture: String
    let ttlDays: Int
}

private struct AddAuthorizationEnvelopeSheet: View {
    @Environment(\.dismiss) private var dismiss
    let onSave: (AuthorizationEnvelopeDraft) -> Void

    @State private var researcherIdentity = ""
    @State private var targetHandle = ""
    @State private var authorizedOrigins = "https://"
    @State private var authorizationBasis = ""
    @State private var allowedWorkflows = ""
    @State private var disclosureAttestation = false
    @State private var maxAccountsPerService = 3
    @State private var legalPosture = ""
    @State private var ttlDays = 30

    private var originValues: [String] {
        splitLines(authorizedOrigins)
    }

    private var workflowValues: [String] {
        splitLines(allowedWorkflows)
    }

    private var canSave: Bool {
        !researcherIdentity.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !targetHandle.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !authorizationBasis.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !originValues.isEmpty
            && !workflowValues.isEmpty
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("NEW AUTHORIZATION ENVELOPE")
                .font(.system(size: 14, weight: .bold, design: .monospaced))
                .foregroundColor(.cyberCyan)

            Text("This is an execution gate, not a target profile. Enter only authority you have already reviewed.")
                .font(.system(size: 11))
                .foregroundColor(.secondary)

            Form {
                TextField("Researcher identity", text: $researcherIdentity)
                TextField("Target or program handle", text: $targetHandle)

                VStack(alignment: .leading, spacing: 4) {
                    Text("Authorized origins — one per line")
                    TextEditor(text: $authorizedOrigins)
                        .font(.system(size: 11, design: .monospaced))
                        .frame(minHeight: 52)
                }

                VStack(alignment: .leading, spacing: 4) {
                    Text("Allowed workflows — one per line")
                    TextEditor(text: $allowedWorkflows)
                        .font(.system(size: 11, design: .monospaced))
                        .frame(minHeight: 72)
                }

                TextField("Authorization basis", text: $authorizationBasis, axis: .vertical)
                    .lineLimit(2...4)
                TextField("Legal posture or policy reference", text: $legalPosture, axis: .vertical)
                    .lineLimit(1...3)
                Stepper(
                    "Maximum accounts per service: \(maxAccountsPerService)",
                    value: $maxAccountsPerService,
                    in: 1...20
                )
                Stepper("Expires after \(ttlDays) days", value: $ttlDays, in: 1...365)
                Toggle(
                    "I attest this work is covered by the disclosed authorization above.",
                    isOn: $disclosureAttestation
                )
                .toggleStyle(.checkbox)
            }
            .formStyle(.grouped)

            if !disclosureAttestation {
                Text("Without the attestation this envelope is stored as unapproved and cannot authorize execution.")
                    .font(.system(size: 10))
                    .foregroundColor(.orange)
            }

            HStack {
                Button("Cancel") { dismiss() }
                    .buttonStyle(.bordered)
                Spacer()
                Button("Save Envelope") {
                    onSave(
                        AuthorizationEnvelopeDraft(
                            researcherIdentity: researcherIdentity.trimmingCharacters(in: .whitespacesAndNewlines),
                            targetHandle: targetHandle.trimmingCharacters(in: .whitespacesAndNewlines),
                            authorizedOrigins: originValues,
                            authorizationBasis: authorizationBasis.trimmingCharacters(in: .whitespacesAndNewlines),
                            allowedWorkflows: workflowValues,
                            disclosureAttestation: disclosureAttestation,
                            maxAccountsPerService: maxAccountsPerService,
                            legalPosture: legalPosture.trimmingCharacters(in: .whitespacesAndNewlines),
                            ttlDays: ttlDays
                        )
                    )
                    dismiss()
                }
                .buttonStyle(.borderedProminent)
                .tint(.cyberCyan)
                .disabled(!canSave)
            }
        }
        .padding(20)
        .frame(width: 560, height: 650)
    }

    private func splitLines(_ value: String) -> [String] {
        value
            .components(separatedBy: .newlines)
            .flatMap { $0.components(separatedBy: ",") }
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty && $0 != "https://" }
    }
}

// MARK: - Record Recipe Sheet

private struct RecordRecipeSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Binding var isRecording: Bool
    let onRecord: (String, String, String) -> Void

    @State private var serviceHandle = ""
    @State private var name = ""
    @State private var origin = "https://"

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("RECORD SIGNUP RECIPE")
                .font(.system(size: 14, weight: .bold, design: .monospaced))
                .foregroundColor(.cyberCyan)

            VStack(alignment: .leading, spacing: 8) {
                Text("Service Handle").font(.system(size: 10, weight: .bold, design: .monospaced))
                TextField("e.g. tiktok", text: $serviceHandle)
                    .textFieldStyle(.roundedBorder)

                Text("Recipe Name").font(.system(size: 10, weight: .bold, design: .monospaced))
                TextField("e.g. standard signup", text: $name)
                    .textFieldStyle(.roundedBorder)

                Text("Origin URL").font(.system(size: 10, weight: .bold, design: .monospaced))
                TextField("e.g. https://tiktok.com/signup", text: $origin)
                    .textFieldStyle(.roundedBorder)
            }
            .font(.system(size: 12, design: .monospaced))

            HStack {
                Button("Cancel") { dismiss() }
                    .buttonStyle(.bordered)
                Spacer()
                Button("Start Recording") {
                    onRecord(serviceHandle, name, origin)
                    dismiss()
                }
                .buttonStyle(.borderedProminent)
                .tint(.cyberCyan)
                .disabled(serviceHandle.isEmpty || name.isEmpty || origin == "https://")
            }
        }
        .padding(20)
        .frame(width: 400)
    }
}


// MARK: - Challenge card

private struct ChallengeCard: View {
    let challenge: FoundryChallenge
    let valueDraft: String
    let onValueChange: (String) -> Void
    let onResolve: () -> Void
    let onDecline: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: iconFor(challenge.kind))
                    .foregroundColor(.orange)
                Text(challenge.kind.uppercased())
                    .font(.system(size: 11, weight: .bold, design: .monospaced))
                    .foregroundColor(.orange)
                Spacer()
                Text(challenge.serviceHandle)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(.white.opacity(0.5))
            }
            // Screenshot (if present) — the human sees the wall.
            if let b64 = challenge.screenshotB64,
               let data = Data(base64Encoded: b64),
               let img = NSImage(data: data) {
                Image(nsImage: img)
                    .resizable()
                    .aspectRatio(contentMode: .fit)
                    .frame(maxWidth: 280, maxHeight: 140)
                    .cornerRadius(4)
            }
            Text(challenge.prompt)
                .font(.system(size: 12))
                .foregroundColor(.white.opacity(0.9))
                .fixedSize(horizontal: false, vertical: true)
            Text(challenge.contextUrl)
                .font(.system(size: 10, design: .monospaced))
                .foregroundColor(.white.opacity(0.45))
                .lineLimit(1)

            // For verification challenges, capture the human's value.
            if challenge.needsValue {
                TextField("paste the code / link here",
                          text: Binding(get: { valueDraft }, set: onValueChange))
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 12, design: .monospaced))
            }

            HStack {
                Button(action: onResolve) {
                    Label(challenge.needsValue ? "Submit" : "Done", systemImage: "checkmark.circle.fill")
                }
                .buttonStyle(.borderedProminent)
                .tint(.green)
                Button(action: onDecline) {
                    Label("Skip", systemImage: "xmark.circle")
                }
                .buttonStyle(.bordered)
                .tint(.red)
            }
        }
        .padding(12)
        .frame(width: 300)
        .background(Color.black.opacity(0.5))
        .cornerRadius(8)
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.orange.opacity(0.4), lineWidth: 1))
    }

    private func iconFor(_ kind: String) -> String {
        switch kind {
        case "captcha": return "checkerboard.shield"
        case "email_link", "email_code": return "envelope.fill"
        case "sms_code": return "message.fill"
        case "payment_3ds": return "creditcard.fill"
        case "tos_scroll": return "doc.text.fill"
        default: return "hand.raised.fill"
        }
    }
}


// MARK: - View model

@MainActor
final class FoundryConsoleViewModel: ObservableObject {
    @Published var challenges: [FoundryChallenge] = []
    @Published var personas: [FoundryPersona] = []
    @Published var envelopes: [FoundryAuthorizationEnvelope] = []
    @Published var selectedEnvelopeId: String = ""
    @Published var recipes: [FoundryRecipeSummary] = []
    @Published var jobs: [FoundrySignupJob] = []
    @Published var plan: FoundryAccountPlan?
    @Published var errorMessage: String?
    @Published var isRecording: Bool = false

    @Published var planTarget: String = "airtable"
    @Published var selectedVulnClasses: Set<String> = ["idor_cross_principal"]
    private var valueDrafts: [String: String] = [:]

    let availableVulnClasses = [
        "idor_cross_principal",
        "idor_horizontal",
        "privilege_escalation",
        "mass_assignment",
        "csrf",
        "open_redirect",
    ]

    private let client = FoundryAPIClient.shared
    private var pollTask: Task<Void, Never>?

    var selectedEnvelope: FoundryAuthorizationEnvelope? {
        envelopes.first { $0.envelopeId == selectedEnvelopeId }
    }

    func start() {
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refresh()
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
        }
    }
    func stop() { pollTask?.cancel(); pollTask = nil }

    func refresh() async {
        do {
            // Challenges first — they're the time-sensitive hero.
            challenges = try await client.listChallenges()
            personas = try await client.listPersonas()
            envelopes = try await client.listAuthorizationEnvelopes()
            recipes = try await client.listRecipes()
            jobs = try await client.listSignupJobs()
            if !selectedEnvelopeId.isEmpty
                && !envelopes.contains(where: { $0.envelopeId == selectedEnvelopeId })
            {
                selectedEnvelopeId = ""
            }
            errorMessage = nil
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func vulnBinding(_ vc: String) -> Binding<Bool> {
        Binding(
            get: { self.selectedVulnClasses.contains(vc) },
            set: { on in
                if on { self.selectedVulnClasses.insert(vc) }
                else { self.selectedVulnClasses.remove(vc) }
            }
        )
    }

    func computePlan() async {
        do {
            plan = try await client.plan(
                targetHandle: planTarget,
                vulnClasses: Array(selectedVulnClasses).sorted())
            errorMessage = nil
        } catch {
            errorMessage = "Plan: \(error.localizedDescription)"
        }
    }

    func envelopeLabel(_ envelope: FoundryAuthorizationEnvelope) -> String {
        let status = envelope.isApproved && !envelope.isExpired ? "approved" : "blocked"
        return "\(envelope.targetHandle) · \(status) · \(envelope.envelopeId.prefix(8))"
    }

    func selectedExecutableEnvelope(
        for recipe: FoundryRecipeSummary
    ) -> FoundryAuthorizationEnvelope? {
        guard let envelope = selectedEnvelope,
              envelope.isApproved,
              !envelope.isExpired,
              let origin = recipe.origin,
              envelope.authorizes(urlOrOrigin: origin),
              envelope.permits(workflow: recipe.serviceHandle)
        else {
            return nil
        }
        return envelope
    }

    func signupRunHelp(for recipe: FoundryRecipeSummary) -> String {
        if personas.isEmpty {
            return "Create a research persona before replaying this recipe."
        }
        guard let envelope = selectedEnvelope else {
            return "Select an approved authorization envelope."
        }
        guard envelope.isApproved && !envelope.isExpired else {
            return "The selected envelope is unapproved or expired."
        }
        guard let origin = recipe.origin,
              envelope.authorizes(urlOrOrigin: origin)
        else {
            return "The selected envelope does not authorize this recipe origin."
        }
        guard envelope.permits(workflow: recipe.serviceHandle) else {
            return "The selected envelope does not permit this recipe workflow."
        }
        return "Replay this recipe under the selected authorization envelope."
    }

    fileprivate func createEnvelope(_ draft: AuthorizationEnvelopeDraft) async {
        do {
            let created = try await client.createAuthorizationEnvelope(
                researcherIdentity: draft.researcherIdentity,
                targetHandle: draft.targetHandle,
                authorizedOrigins: draft.authorizedOrigins,
                authorizationBasis: draft.authorizationBasis,
                allowedWorkflows: draft.allowedWorkflows,
                disclosureAttestation: draft.disclosureAttestation,
                maxAccountsPerService: draft.maxAccountsPerService,
                legalPosture: draft.legalPosture,
                ttlDays: draft.ttlDays
            )
            await refresh()
            selectedEnvelopeId = created.envelopeId
            errorMessage = nil
        } catch {
            errorMessage = "Envelope: \(error.localizedDescription)"
        }
    }

    func startSignup(recipe: FoundryRecipeSummary, personaId: String) async {
        guard let envelope = selectedExecutableEnvelope(for: recipe) else {
            errorMessage = signupRunHelp(for: recipe)
            return
        }
        do {
            _ = try await client.startSignup(
                recipeId: recipe.recipeId,
                personaId: personaId,
                envelopeId: envelope.envelopeId
            )
            await refresh()
        } catch {
            errorMessage = "Signup: \(error.localizedDescription)"
        }
    }
    
    func recordRecipe(serviceHandle: String, name: String, origin: String) async {
        isRecording = true
        errorMessage = nil
        do {
            _ = try await client.recordRecipe(serviceHandle: serviceHandle, name: name, origin: origin)
            await refresh()
        } catch {
            errorMessage = "Record: \(error.localizedDescription)"
        }
        isRecording = false
    }

    // Challenge handoff
    @MainActor
    func deleteRecipe(recipeId: String) async {
        do {
            try await FoundryAPIClient.shared.deleteRecipe(recipeId: recipeId)
            await refresh()
        } catch {
            self.errorMessage = "Delete error: \(error.localizedDescription)"
        }
    }

    func bindingValueDraft(_ id: String) -> String { valueDrafts[id] ?? "" }
    func setValueDraft(_ id: String, _ value: String) { valueDrafts[id] = value }

    func resolve(_ challenge: FoundryChallenge, resolved: Bool) async {
        do {
            let value = challenge.needsValue ? (valueDrafts[challenge.challengeId] ?? "") : nil
            _ = try await client.resolveChallenge(
                challenge.challengeId, resolved: resolved, extractedValue: value)
            valueDrafts[challenge.challengeId] = nil
            await refresh()
        } catch {
            errorMessage = "Resolve: \(error.localizedDescription)"
        }
    }
}
