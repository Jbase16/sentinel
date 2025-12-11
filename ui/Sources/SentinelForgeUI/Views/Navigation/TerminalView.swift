import SwiftUI
import WebKit

struct TerminalView: NSViewRepresentable {
    func makeNSView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        // Allow local file access if needed, though we serve via HTTP usually? 
        // No, we are loading a local HTML file that connects to localhost WS.
        config.preferences.setValue(true, forKey: "allowFileAccessFromFileURLs")
        
        let webView = WKWebView(frame: .zero, configuration: config)
        
        if let resourceUrl = Bundle.main.url(forResource: "index", withExtension: "html", subdirectory: "SentinelForgeUI/Resources/terminal") 
           ?? Bundle.module.url(forResource: "index", withExtension: "html", subdirectory: "SentinelForgeUI/Resources/terminal") {
            webView.loadFileURL(resourceUrl, allowingReadAccessTo: resourceUrl.deletingLastPathComponent())
        } else {
            // Fallback: Load directly from string if file not found (debug)
            // Or try standard bundle path
             if let url = Bundle.main.url(forResource: "index", withExtension: "html") {
                 webView.loadFileURL(url, allowingReadAccessTo: url.deletingLastPathComponent())
             }
        }
        
        return webView
    }

    func updateNSView(_ nsView: WKWebView, context: Context) {}
}
