import WebKit

let webView = WKWebView()
webView.evaluateJavaScript("navigator.userAgent") { result, error in
    if let ua = result as? String {
        print(ua)
    } else {
        print("Error: \(String(describing: error))")
    }
    exit(0)
}
RunLoop.main.run()
