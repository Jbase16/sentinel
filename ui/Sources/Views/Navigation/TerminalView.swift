// ============================================================================
// ui/Sources/Views/Navigation/TerminalView.swift
// Terminalview Component
// ============================================================================
//
// PURPOSE:
// This Swift component is part of the SentinelForge macOS UI.
// [Specific purpose based on component name: TerminalView]
//
// KEY RESPONSIBILITIES:
// - [Automatically generated - review and enhance based on actual functionality]
//
// INTEGRATION:
// - Used by: [To be documented]
// - Depends on: [To be documented]
//
// ============================================================================

import SwiftUI
import WebKit

struct TerminalView: NSViewRepresentable {
    func makeNSView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        // Allow local access
        config.preferences.setValue(true, forKey: "allowFileAccessFromFileURLs")
        
        let webView = WKWebView(frame: .zero, configuration: config)
        
        // Embedded HTML to avoid bundle resource issues
        let html = """
        <!doctype html>
        <html>
          <head>
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css" />
            <script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.js"></script>
            <script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.js"></script>
            <style>
              body { margin: 0; padding: 0; background: #1e1e1e; height: 100vh; overflow: hidden; }
              #terminal { width: 100%; height: 100%; }
            </style>
          </head>
          <body>
            <div id="terminal"></div>
            <script>
              const term = new Terminal({
                theme: { background: '#1e1e1e' },
                fontFamily: 'Menlo, Monaco, "Courier New", monospace',
                fontSize: 14,
                cursorBlink: true
              });
              const fitAddon = new FitAddon.FitAddon();
              term.loadAddon(fitAddon);
              term.open(document.getElementById('terminal'));
              fitAddon.fit();

              // Connect to backend WebSocket
              const ws = new WebSocket("ws://127.0.0.1:8765/ws/terminal");

              term.onData(data => {
                if (ws.readyState === WebSocket.OPEN) {
                    ws.send(data);
                }
              });

              ws.onmessage = event => {
                term.write(event.data);
              };

              ws.onopen = () => {
                term.write('\\x1b[32m[Sentinel Terminal Connected]\\x1b[0m\\r\\n');
                ws.send(JSON.stringify({type: 'resize', cols: term.cols, rows: term.rows}));
              };
              
              ws.onclose = () => {
                term.write('\\r\\n\\x1b[31m[Connection Lost - Restart Backend]\\x1b[0m');
              };

              window.addEventListener('resize', () => {
                fitAddon.fit();
                if(ws.readyState === WebSocket.OPEN) {
                     ws.send(JSON.stringify({type: 'resize', cols: term.cols, rows: term.rows}));
                }
              });
            </script>
          </body>
        </html>
        """;
        
        webView.loadHTMLString(html, baseURL: nil)
        return webView
    }

    func updateNSView(_ nsView: WKWebView, context: Context) {}
}