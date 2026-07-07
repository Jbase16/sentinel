import Cocoa
import WebKit

class AppDelegate: NSObject, NSApplicationDelegate {
    var window: NSWindow!
    var webView: WKWebView!
    
    func applicationDidFinishLaunching(_ notification: Notification) {
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 800, height: 600),
                          styleMask: [.titled, .closable, .resizable],
                          backing: .buffered, defer: false)
        webView = WKWebView(frame: window.contentView!.bounds)
        window.contentView?.addSubview(webView)
        window.makeKeyAndOrderFront(nil)
        
        let req = URLRequest(url: URL(string: "https://www.whatnot.com/")!)
        webView.load(req)
        
        DispatchQueue.main.asyncAfter(deadline: .now() + 15.0) {
            self.webView.configuration.websiteDataStore.httpCookieStore.getAllCookies { cookies in
                var dicts = [String: String]()
                for c in cookies {
                    dicts[c.name] = c.value
                }
                let jsonData = try! JSONSerialization.data(withJSONObject: dicts, options: [])
                let jsonString = String(data: jsonData, encoding: .utf8)!
                print("COOKIES_JSON: " + jsonString)
                
                self.webView.evaluateJavaScript("navigator.userAgent") { res, err in
                    print("UA: \(res as? String ?? "")")
                    NSApplication.shared.terminate(self)
                }
            }
        }
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
