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

    let userContentController = WKUserContentController()
    userContentController.add(context.coordinator, name: "pty")
    config.userContentController = userContentController

    let webView = WKWebView(frame: .zero, configuration: config)
    context.coordinator.webView = webView

    if let htmlURL = Bundle.main.url(forResource: "index", withExtension: "html") {
      webView.loadFileURL(htmlURL, allowingReadAccessTo: htmlURL.deletingLastPathComponent())
    } else {
      webView.loadHTMLString("<p>Terminal resources are unavailable.</p>", baseURL: nil)
    }

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
        client.connect(url: SentinelRuntimeEndpoint.webSocketURL("/ws/pty"))
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
