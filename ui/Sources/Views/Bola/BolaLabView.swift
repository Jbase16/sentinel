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
    @Published var actorStatuses: [String: String] = [:]
    @Published var isCapturing: [String: Bool] = [:]
    
    private let baseURL = "http://127.0.0.1:8765/v1/driver"
    
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
        } catch {
            print("BolaLabViewModel failed to fetch personas: \(error)")
        }
    }
    
    func startCapture(for persona: FoundryPersona) {
        let savePanel = NSSavePanel()
        savePanel.title = "Save Capture File for \(persona.label)"
        savePanel.nameFieldStringValue = "\(persona.label.lowercased())_output.jsonl"
        savePanel.canCreateDirectories = true
        
        savePanel.begin { result in
            if result == .OK, let url = savePanel.url {
                Task {
                    await self.executeStartCapture(url: self.targetUrl, filePath: url.path, persona: persona)
                }
            }
        }
    }
    
    private func executeStartCapture(url: String, filePath: String, persona: FoundryPersona) async {
        isCapturing[persona.personaId] = true
        actorStatuses[persona.personaId] = "Capturing to \(filePath)..."
        
        do {
            guard let endpoint = URL(string: "\(baseURL)/start_capture") else { return }
            var request = URLRequest(url: endpoint)
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            
            let payload: [String: Any] = [
                "url": url,
                "capture_file": filePath
            ]
            request.httpBody = try JSONSerialization.data(withJSONObject: payload)
            
            let (data, _) = try await URLSession.shared.data(for: request)
            
            if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let status = json["status"] as? String, status == "error",
               let msg = json["message"] as? String {
                actorStatuses[persona.personaId] = "Error: \(msg)"
                isCapturing[persona.personaId] = false
                return
            }
        } catch {
            actorStatuses[persona.personaId] = "Error: \(error.localizedDescription)"
            isCapturing[persona.personaId] = false
        }
    }
    
    func stopCapture(for persona: FoundryPersona) {
        Task {
            do {
                guard let endpoint = URL(string: "\(baseURL)/stop_capture") else { return }
                var request = URLRequest(url: endpoint)
                request.httpMethod = "POST"
                
                let (_, _) = try await URLSession.shared.data(for: request)
                
                actorStatuses[persona.personaId] = "Saved."
                isCapturing[persona.personaId] = false
            } catch {
                actorStatuses[persona.personaId] = "Stop Error: \(error.localizedDescription)"
                isCapturing[persona.personaId] = false
            }
        }
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
            
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 30) {
                    ForEach(Array(vm.personas.enumerated()), id: \.element.personaId) { index, persona in
                        actorPanel(
                            name: persona.label,
                            status: vm.actorStatuses[persona.personaId] ?? "Idle",
                            isCapturing: vm.isCapturing[persona.personaId] ?? false,
                            color: panelColors[index % panelColors.count]
                        ) {
                            vm.startCapture(for: persona)
                        } onStop: {
                            vm.stopCapture(for: persona)
                        } onOpenWindow: {
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
                            
                            DriverBridgeClient.shared.personaWindows[persona.label] = window
                            
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
    
    private func actorPanel(name: String, status: String, isCapturing: Bool, color: Color, onStart: @escaping () -> Void, onStop: @escaping () -> Void, onOpenWindow: @escaping () -> Void) -> some View {
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
                .disabled(isCapturing && !status.contains("Capturing"))
                
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
