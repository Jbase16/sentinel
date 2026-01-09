//
//  TimelineView.swift
//  SentinelForgeUI
//
//  The Time Travel Scrubber.
//  Allows navigation through the Event Sourced history.
//

import SwiftUI

struct SentinelTimelineView: View {
    @EnvironmentObject var appState: HelixAppState

    // Local drag state for smooth scrubbing
    @State private var dragProgress: Double? = nil

    var body: some View {
        VStack(spacing: 0) {
            Divider()
                .background(Color.white.opacity(0.1))

            HStack(spacing: 16) {
                // 1. Playback Controls
                Button(action: toggleReplay) {
                    Image(
                        systemName: appState.isReplaying ? "pause.fill" : "clock.arrow.circlepath"
                    )
                    .font(.system(size: 14))
                    .foregroundColor(appState.isReplaying ? .yellow : .cyan)
                }
                .buttonStyle(.plain)
                .help(appState.isReplaying ? "Exit Replay Mode" : "Enter Time Travel")

                // 2. Scrubber
                GeometryReader { geo in
                    ZStack(alignment: .leading) {
                        // Background Track
                        Rectangle()
                            .fill(Color.white.opacity(0.1))
                            .frame(height: 4)
                            .cornerRadius(2)

                        // Progress Fill
                        let total = Double(max(1, appState.allEvents.count))
                        let current = Double(appState.replayCursor ?? appState.allEvents.count)
                        // If dragging, use dragProgress
                        let displayProgress = dragProgress ?? (current / total)

                        Rectangle()
                            .fill(appState.isReplaying ? Color.yellow : Color.cyan)
                            .frame(
                                width: geo.size.width * CGFloat(max(0, min(1, displayProgress))),
                                height: 4
                            )
                            .cornerRadius(2)

                        // Handle
                        Circle()
                            .fill(Color.white)
                            .frame(width: 12, height: 12)
                            .shadow(radius: 2)
                            .position(
                                x: geo.size.width * CGFloat(max(0, min(1, displayProgress))), y: 2)
                    }
                    .frame(height: 12)  // Touch target height
                    .gesture(
                        DragGesture()
                            .onChanged { value in
                                if !appState.isReplaying {
                                    appState.enterReplayMode()
                                }
                                let progress = max(0, min(1, value.location.x / geo.size.width))
                                dragProgress = progress

                                // Live update? Or throttle?
                                // For performance, maybe throttle updates to seek()
                                let total = Double(appState.allEvents.count)
                                let targetIndex = Int(progress * total)
                                appState.seek(to: targetIndex)
                            }
                            .onEnded { value in
                                dragProgress = nil
                                let progress = max(0, min(1, value.location.x / geo.size.width))
                                let total = Double(appState.allEvents.count)
                                let targetIndex = Int(progress * total)
                                appState.seek(to: targetIndex)
                            }
                    )
                }
                .frame(height: 12)

                // 3. Info
                Text(timestampText)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(.white.opacity(0.6))
                    .frame(width: 120, alignment: .trailing)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
            .background(Color.black.opacity(0.8))
        }
    }

    private var timestampText: String {
        if let cursor = appState.replayCursor, cursor < appState.allEvents.count {
            let event = appState.allEvents[cursor]
            // Format timestamp (assume ISO or float in event?)
            // event.timestamp is Double (UNIX)
            return formatTimestamp(event.timestamp)
        } else {
            return "LIVE"
        }
    }

    private func toggleReplay() {
        if appState.isReplaying {
            appState.exitReplayMode()
        } else {
            appState.enterReplayMode()
        }
    }

    private func formatTimestamp(_ ts: Double) -> String {
        let date = Date(timeIntervalSince1970: ts)
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss.SSS"
        return formatter.string(from: date)
    }
}
