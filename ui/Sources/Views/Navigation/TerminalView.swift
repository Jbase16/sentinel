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

import SwiftUI
import WebKit

/// Struct TerminalView.
struct TerminalView: NSViewRepresentable {
  func makeCoordinator() -> Coordinator {
    Coordinator(self)
  }

  /// Function makeNSView.
  func makeNSView(context: Context) -> WKWebView {
    let config = WKWebViewConfiguration()
    config.preferences.setValue(true, forKey: "allowFileAccessFromFileURLs")

    let userContentController = WKUserContentController()
    userContentController.add(context.coordinator, name: "pty")
    config.userContentController = userContentController

    let webView = WKWebView(frame: .zero, configuration: config)
    context.coordinator.webView = webView

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

            // Bridge: Send Input to Swift
            term.onData(data => {
              window.webkit.messageHandlers.pty.postMessage({
                  type: "input",
                  data: data
              });
            });

            window.addEventListener('resize', () => {
              // Debounce resize events
              clearTimeout(window.resizeTimer);
              window.resizeTimer = setTimeout(() => {
                 fitAddon.fit();
                 window.webkit.messageHandlers.pty.postMessage({
                     type: "resize",
                     cols: term.cols,
                     rows: term.rows
                 });
              }, 100);
            });

            // Bridge: Receive Output from Swift
            window.receiveOutput = function(text) {
              term.write(text);
            }
            
            // Initial connect signal
            window.webkit.messageHandlers.pty.postMessage({type: "ready"});
          </script>
        </body>
      </html>
      """

    webView.loadHTMLString(html, baseURL: nil)

    // Connect PTY Client logic is in Coordinator
    return webView
  }

  /// Function updateNSView.
  func updateNSView(_ nsView: WKWebView, context: Context) {}

  // MARK: - Coordinator (The Bridge)

  class Coordinator: NSObject, WKScriptMessageHandler, PTYClientDelegate {
    var parent: TerminalView
    var webView: WKWebView?
    let client = PTYClient()

    init(_ parent: TerminalView) {
      self.parent = parent
      super.init()
      self.client.delegate = self
    }

    func userContentController(
      _ userContentController: WKUserContentController, didReceive message: WKScriptMessage
    ) {
      guard let dict = message.body as? [String: Any],
        let type = dict["type"] as? String
      else { return }

      switch type {
      case "ready":
        // Start connection
        if let url = URL(string: "ws://127.0.0.1:8765/v1/ws/pty") {
          client.connect(url: url)
        }
      case "input":
        if let data = dict["data"] as? String {
          client.write(data)
        }
      case "resize":
        if let cols = dict["cols"] as? Int, let rows = dict["rows"] as? Int {
          client.sendResize(rows: rows, cols: cols)
        }
      default: break
      }
    }

    // PTYDelegate Methods

    func onOutputReceived(_ text: String) {
      // Use JSONSerialization for safe JS string injection
      // avoid manual escaping fragility
      if let data = try? JSONSerialization.data(withJSONObject: [text]),
        let arg = String(data: data, encoding: .utf8)
      {
        // data is array ["text"], so access [0] in JS
        let js = "window.receiveOutput(\(arg)[0]);"
        webView?.evaluateJavaScript(js)
      }
    }

    func onConnectionStateChanged(isConnected: Bool) {
      if isConnected {
        let js = "term.write('\\x1b[32m[Sentinel Terminal Connected]\\x1b[0m\\r\\n');"
        webView?.evaluateJavaScript(js)
      } else {
        let js = "term.write('\\r\\n\\x1b[31m[Connection Lost]\\x1b[0m');"
        webView?.evaluateJavaScript(js)
      }
    }
  }
}
