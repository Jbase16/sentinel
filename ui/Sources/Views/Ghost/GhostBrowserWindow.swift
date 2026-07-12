import AppKit
import WebKit

public class GhostBrowserWindow: NSWindow, WKNavigationDelegate, WKScriptMessageHandler, WKUIDelegate {
    private struct CaptureOrigin: Equatable {
        let scheme: String
        let host: String
        let port: Int

        init?(url: URL) {
            guard let rawScheme = url.scheme?.lowercased(),
                  ["http", "https"].contains(rawScheme),
                  let rawHost = url.host?.lowercased(),
                  !rawHost.isEmpty else { return nil }
            scheme = rawScheme
            host = rawHost
            port = url.port ?? (rawScheme == "https" ? 443 : 80)
        }
    }

    private var webView: WKWebView!
    public var onClose: (() -> Void)?
    
    // For waiting on navigation
    private var navigationContinuation: CheckedContinuation<Void, Error>?
    private var networkCapturePersonaId = ""
    private var networkCaptureSessionId = ""
    private var networkCaptureEnabled = false
    private var networkCaptureScriptCount = 0
    private var networkCaptureOrigin: CaptureOrigin?
    private var mainFrameResponseStatus = 0
    
    public override init(contentRect: NSRect, styleMask style: NSWindow.StyleMask, backing backingStoreType: NSWindow.BackingStoreType, defer flag: Bool) {
        super.init(contentRect: contentRect, styleMask: style, backing: backingStoreType, defer: flag)
        
        self.title = "Sentinel Native Driver"
        self.isReleasedWhenClosed = false
        
        let config = WKWebViewConfiguration()
        config.websiteDataStore = WKWebsiteDataStore.nonPersistent()
        // Ensure script message handler is ready for recording
        let userContentController = WKUserContentController()
        userContentController.add(self, name: "sndRecordingBridge")
        config.userContentController = userContentController
        
        webView = WKWebView(frame: contentRect, configuration: config)
        webView.navigationDelegate = self
        webView.uiDelegate = self
        self.contentView = webView
        
        // Disable cross-origin restrictions if possible
        webView.configuration.preferences.setValue(true, forKey: "developerExtrasEnabled")
    }
    
    public override func close() {
        onClose?()
        super.close()
    }
    
    // MARK: - Navigation Delegate
    
    public func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        let continuation = navigationContinuation
        navigationContinuation = nil
        captureMainFrameIfEnabled {
            continuation?.resume()
        }
    }

    public func webView(
        _ webView: WKWebView,
        decidePolicyFor navigationResponse: WKNavigationResponse,
        decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void
    ) {
        if navigationResponse.isForMainFrame,
           let response = navigationResponse.response as? HTTPURLResponse {
            mainFrameResponseStatus = response.statusCode
        }
        decisionHandler(.allow)
    }

    public func webView(
        _ webView: WKWebView,
        decidePolicyFor navigationAction: WKNavigationAction,
        decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
    ) {
        guard networkCaptureEnabled,
              navigationAction.targetFrame?.isMainFrame == true,
              let requestedURL = navigationAction.request.url else {
            decisionHandler(.allow)
            return
        }
        guard let allowedOrigin = networkCaptureOrigin,
              CaptureOrigin(url: requestedURL) == allowedOrigin else {
            decisionHandler(.cancel)
            let error = NSError(
                domain: "SND",
                code: 403,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "Capture blocked a cross-origin main-frame navigation"
                ]
            )
            navigationContinuation?.resume(throwing: error)
            navigationContinuation = nil
            return
        }
        decisionHandler(.allow)
    }
    
    public func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        navigationContinuation?.resume(throwing: error)
        navigationContinuation = nil
    }
    
    public func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        navigationContinuation?.resume(throwing: error)
        navigationContinuation = nil
    }

    private func captureMainFrameIfEnabled(completion: @escaping () -> Void) {
        guard networkCaptureEnabled,
              let url = webView.url?.absoluteString,
              !url.isEmpty else {
            completion()
            return
        }
        let personaId = networkCapturePersonaId
        let captureSessionId = networkCaptureSessionId
        let status = mainFrameResponseStatus
        let js = """
        (() => {
            const raw = document.body?.innerText
                || document.documentElement?.innerText || '';
            const limit = 2097152;
            return {
                body: raw.slice(0, limit),
                truncated: raw.length > limit
            };
        })();
        """
        webView.evaluateJavaScript(js) { value, _ in
            let capture = value as? [String: Any]
            DriverBridgeClient.shared.sendSpontaneousEvent(
                event: "recorded_action",
                payload: [
                    "action": [
                        "action": "network_capture",
                        "persona_id": personaId,
                        "capture_session": captureSessionId,
                        "type": "navigation",
                        "url": url,
                        "method": "GET",
                        "request_headers": [:],
                        "request_body": "",
                        "response_status": status,
                        "response_body": capture?["body"] as? String ?? "",
                        "response_truncated": capture?["truncated"] as? Bool ?? false,
                    ]
                ]
            )
            completion()
        }
    }
    
    // MARK: - UI Delegate
    
    public func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration, for navigationAction: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        if navigationAction.targetFrame == nil {
            webView.load(navigationAction.request)
        }
        return nil
    }
    
    // MARK: - API
    
    public func callAsyncJavaScript(_ script: String, arguments: [String: Any], in world: WKContentWorld = .page) async throws -> Any? {
        return try await webView.callAsyncJavaScript(script, arguments: arguments, in: nil, in: world)
    }
    
    public func navigate(url: String) async throws {
        guard let nsurl = URL(string: url) else {
            throw NSError(domain: "SND", code: 400, userInfo: [NSLocalizedDescriptionKey: "Invalid URL"])
        }
        if networkCaptureEnabled {
            guard let origin = CaptureOrigin(url: nsurl) else {
                throw NSError(
                    domain: "SND",
                    code: 400,
                    userInfo: [NSLocalizedDescriptionKey: "Invalid capture origin"]
                )
            }
            networkCaptureOrigin = origin
        }
        
        return try await withCheckedThrowingContinuation { continuation in
            self.mainFrameResponseStatus = 0
            self.navigationContinuation = continuation
            webView.load(URLRequest(url: nsurl))
        }
    }
    
    public func currentUrl() async throws -> String {
        return await MainActor.run { webView.url?.absoluteString ?? "" }
    }
    
    public func screenshotBase64() async throws -> String {
        let config = WKSnapshotConfiguration()
        return try await withCheckedThrowingContinuation { continuation in
            webView.takeSnapshot(with: config) { image, error in
                if let err = error {
                    continuation.resume(throwing: err)
                    return
                }
                guard let img = image,
                      let cgImage = img.cgImage(forProposedRect: nil, context: nil, hints: nil) else {
                    continuation.resume(throwing: NSError(domain: "SND", code: 500, userInfo: [NSLocalizedDescriptionKey: "Failed to take snapshot"]))
                    return
                }
                let bitmapRep = NSBitmapImageRep(cgImage: cgImage)
                if let pngData = bitmapRep.representation(using: .png, properties: [:]) {
                    continuation.resume(returning: pngData.base64EncodedString())
                } else {
                    continuation.resume(throwing: NSError(domain: "SND", code: 500, userInfo: [NSLocalizedDescriptionKey: "Failed to encode PNG"]))
                }
            }
        }
    }
    
    public func getCookies() async throws -> [String: String] {
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.main.async {
                self.webView.configuration.websiteDataStore.httpCookieStore.getAllCookies { cookies in
                    var cookieDict: [String: String] = [:]
                    for cookie in cookies {
                        cookieDict[cookie.name] = cookie.value
                    }
                    continuation.resume(returning: cookieDict)
                }
            }
        }
    }
    
    // MARK: - Selectors & Eval
    
    private func buildJsSelector(_ selector: [String: String]) -> String {
        let by = selector["by"] ?? ""
        let val = selector["value"] ?? ""
        
        switch by {
        case "css":
            return "document.querySelector('\(val)')"
        case "name":
            return "document.querySelector('[name=\"\(val)\"]')"
        case "placeholder":
            return "Array.from(document.querySelectorAll('input,textarea')).find(el => el.placeholder === '\(val)')"
        case "text":
            return """
            Array.from(document.querySelectorAll('*')).reverse().find(el => {
                if (el.textContent.trim() !== '\(val)') return false;
                let rect = el.getBoundingClientRect();
                return rect.width > 0 && rect.height > 0;
            })
            """
        default:
            return "document.querySelector('\(val)')"
        }
    }
    
    private func getBoundingRect(selector: [String: String], timeoutS: TimeInterval = 10.0) async throws -> CGRect {
        let jsSelector = buildJsSelector(selector)
        let js = """
        (function() {
            var el = \(jsSelector);
            if (!el) return null;
            var rect = el.getBoundingClientRect();
            return {x: rect.x, y: rect.y, width: rect.width, height: rect.height};
        })();
        """
        
        let startTime = Date()
        while Date().timeIntervalSince(startTime) < timeoutS {
            if let result = try? await webView.evaluateJavaScript(js),
               let dict = result as? [String: Any],
               let x = dict["x"] as? CGFloat,
               let y = dict["y"] as? CGFloat,
               let w = dict["width"] as? CGFloat,
               let h = dict["height"] as? CGFloat {
                return CGRect(x: x, y: y, width: w, height: h)
            }
            try await Task.sleep(nanoseconds: 200_000_000) // 200ms
        }
        
        throw NSError(domain: "SND", code: 404, userInfo: [NSLocalizedDescriptionKey: "Element not found (\(jsSelector)) after \(timeoutS)s"])
    }
    
    public func waitFor(selector: [String: String], timeoutS: TimeInterval) async throws {
        _ = try await getBoundingRect(selector: selector, timeoutS: timeoutS)
    }
    
    // MARK: - Hardware Event Synthesis
    
    public func click(selector: [String: String]) async throws {
        let rect = try await getBoundingRect(selector: selector)
        let centerWebX = rect.midX
        let centerWebY = rect.midY
        
        // WKWebView is flipped (y=0 is top). getBoundingClientRect returns y=0 at top.
        // We can just create the point directly.
        let viewPoint = NSPoint(x: centerWebX, y: centerWebY)
        
        // Convert NSView coordinates to window coordinates
        let windowPoint = webView.convert(viewPoint, to: nil)
        
        // Synthesize NSEvents!
        guard let evtDown = NSEvent.mouseEvent(
            with: .leftMouseDown,
            location: windowPoint,
            modifierFlags: [],
            timestamp: ProcessInfo.processInfo.systemUptime,
            windowNumber: self.windowNumber,
            context: nil,
            eventNumber: 0,
            clickCount: 1,
            pressure: 1.0
        ) else { return }
        
        guard let evtUp = NSEvent.mouseEvent(
            with: .leftMouseUp,
            location: windowPoint,
            modifierFlags: [],
            timestamp: ProcessInfo.processInfo.systemUptime,
            windowNumber: self.windowNumber,
            context: nil,
            eventNumber: 0,
            clickCount: 1,
            pressure: 0.0
        ) else { return }
        
        self.sendEvent(evtDown)
        try await Task.sleep(nanoseconds: 50_000_000) // 50ms hold
        self.sendEvent(evtUp)
    }
    
    public func fill(selector: [String: String], value: String) async throws {
        // First click to focus
        try await click(selector: selector)
        try await Task.sleep(nanoseconds: 100_000_000)
        
        // Clear the field first by selecting all and deleting? (Optional, skipping for now)
        
        // Synthesize keystrokes for each character
        for char in value {
            guard let utf16 = String(char).utf16.first else { continue }
            
            // Generate KeyDown
            if let evtDown = NSEvent.keyEvent(
                with: .keyDown,
                location: .zero,
                modifierFlags: [],
                timestamp: ProcessInfo.processInfo.systemUptime,
                windowNumber: self.windowNumber,
                context: nil,
                characters: String(char),
                charactersIgnoringModifiers: String(char),
                isARepeat: false,
                keyCode: 0 // Virtual keycode doesn't matter as much as characters
            ) {
                self.sendEvent(evtDown)
            }
            
            try await Task.sleep(nanoseconds: 20_000_000)
            
            if let evtUp = NSEvent.keyEvent(
                with: .keyUp,
                location: .zero,
                modifierFlags: [],
                timestamp: ProcessInfo.processInfo.systemUptime,
                windowNumber: self.windowNumber,
                context: nil,
                characters: String(char),
                charactersIgnoringModifiers: String(char),
                isARepeat: false,
                keyCode: 0
            ) {
                self.sendEvent(evtUp)
            }
            
            try await Task.sleep(nanoseconds: 30_000_000)
        }
    }
    
    public func extract(selector: [String: String], mode: String) async throws -> String {
        let jsSelector = buildJsSelector(selector)
        var js = ""
        if mode == "text" {
            js = "(\(jsSelector)).textContent"
        } else if mode == "value" {
            js = "(\(jsSelector)).value"
        } else if mode.starts(with: "attr:") {
            let attr = String(mode.dropFirst(5))
            js = "(\(jsSelector)).getAttribute('\(attr)')"
        } else {
            js = "(\(jsSelector)).textContent"
        }
        
        let timeoutS: TimeInterval = 10.0
        let startTime = Date()
        while Date().timeIntervalSince(startTime) < timeoutS {
            if let result = try? await webView.evaluateJavaScript(js), let val = result as? String, !val.isEmpty {
                return val
            }
            try await Task.sleep(nanoseconds: 200_000_000)
        }
        return ""
    }
    
    // MARK: - Recording Hook
    
    public func startRecording() async throws {
        let js = """
        function getCssPath(el) {
            if (!(el instanceof Element)) return '';
            var path = [];
            while (el.nodeType === Node.ELEMENT_NODE) {
                var selector = el.nodeName.toLowerCase();
                if (el.id) {
                    selector += '#' + el.id;
                    path.unshift(selector);
                    break;
                } else {
                    var sib = el, nth = 1;
                    while (sib = sib.previousElementSibling) { nth++; }
                    selector += ":nth-child("+nth+")";
                }
                path.unshift(selector);
                el = el.parentNode;
            }
            return path.join(" > ");
        }
        
        function getBestSelector(el) {
            if (el.id) return {by: 'css', value: el.tagName.toLowerCase() + '#' + el.id};
            if (el.name) return {by: 'name', value: el.name};
            if (el.placeholder) return {by: 'placeholder', value: el.placeholder};
            if ((el.tagName === 'BUTTON' || el.tagName === 'A') && el.textContent.trim().length > 0 && el.textContent.trim().length < 50) {
                return {by: 'text', value: el.textContent.trim()};
            }
            return {by: 'css', value: getCssPath(el)};
        }
        
        document.addEventListener('change', e => {
            if (!e.target || e.target.tagName === 'BODY') return;
            const t = e.target;
            window.webkit.messageHandlers.sndRecordingBridge.postMessage({
                action: 'fill',
                selector: getBestSelector(t),
                field: {
                    name: t.name || '',
                    id: t.id || '',
                    type: t.type || '',
                    placeholder: t.placeholder || '',
                    autocomplete: t.autocomplete || '',
                    'aria-label': t.getAttribute('aria-label') || ''
                }
            });
        }, {capture: true});
        
        document.addEventListener('click', e => {
            if (!e.target || e.target.tagName === 'BODY') return;
            const t = e.target;
            if (t.tagName === 'IFRAME') {
                let src = (t.src || '').toLowerCase();
                let kind = 'captcha'; // fallback
                if (src.includes('recaptcha')) kind = 'recaptcha';
                else if (src.includes('turnstile')) kind = 'turnstile';
                
                window.webkit.messageHandlers.sndRecordingBridge.postMessage({
                    action: 'challenge',
                    challenge_kind: kind
                });
                return;
            }
            window.webkit.messageHandlers.sndRecordingBridge.postMessage({
                action: 'click',
                selector: getBestSelector(t)
            });
        }, {capture: true});
        """
        
        let script = WKUserScript(source: js, injectionTime: .atDocumentEnd, forMainFrameOnly: false)
        webView.configuration.userContentController.addUserScript(script)
        
        // Also evaluate it right now for the current page
        _ = try? await webView.evaluateJavaScript(js)
    }
    
    public func startNetworkCapture(
        personaId: String? = nil,
        captureSessionId: String
    ) throws {
        guard networkCaptureScriptCount < 128 else {
            throw NSError(
                domain: "SND",
                code: 429,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "Capture script limit reached; reopen this persona window"
                ]
            )
        }
        networkCapturePersonaId = personaId ?? ""
        networkCaptureSessionId = captureSessionId
        networkCaptureEnabled = true
        let personaData = try JSONEncoder().encode(personaId ?? "")
        let captureSessionData = try JSONEncoder().encode(captureSessionId)
        guard let personaLiteral = String(data: personaData, encoding: .utf8),
              let captureSessionLiteral = String(
                  data: captureSessionData,
                  encoding: .utf8
              ) else {
            throw NSError(
                domain: "SND",
                code: 500,
                userInfo: [NSLocalizedDescriptionKey: "Could not encode capture context"]
            )
        }
        let js = """
        (function() {
            window._sndCapturePersonaId = \(personaLiteral);
            window._sndCaptureSessionId = \(captureSessionLiteral);
            window._sndNetworkCaptureEnabled = true;
            if (window._sndNetworkCaptureInitialized) return;
            window._sndNetworkCaptureInitialized = true;

            const MAX_REQUEST_CHARS = 262144;
            const MAX_RESPONSE_CHARS = 2097152;

            function absoluteURL(value) {
                try { return new URL(value, document.baseURI).href; }
                catch (_) { return String(value || ''); }
            }

            function boundedText(value, limit) {
                const text = typeof value === 'string' ? value : '';
                return {text: text.slice(0, limit), truncated: text.length > limit};
            }

            function currentCaptureContext() {
                return {
                    persona_id: window._sndCapturePersonaId,
                    capture_session: window._sndCaptureSessionId
                };
            }

            function postNetworkActivity(context, phase) {
                try {
                    window.webkit.messageHandlers.sndRecordingBridge.postMessage({
                        action: 'network_activity',
                        persona_id: context.persona_id,
                        capture_session: context.capture_session,
                        phase: phase
                    });
                } catch (_) {}
            }

            function captureStillCurrent(context) {
                return window._sndNetworkCaptureEnabled
                    && window._sndCapturePersonaId === context.persona_id
                    && window._sndCaptureSessionId === context.capture_session;
            }

            async function readBoundedResponse(response, limit) {
                if (!response.body || typeof response.body.getReader !== 'function') {
                    return boundedText(await response.text(), limit);
                }
                const reader = response.body.getReader();
                const decoder = new TextDecoder();
                let text = '';
                let truncated = false;
                while (true) {
                    const part = await reader.read();
                    if (part.done) break;
                    const decoded = decoder.decode(part.value, {stream: true});
                    const remaining = limit - text.length;
                    if (decoded.length > remaining) {
                        text += decoded.slice(0, Math.max(0, remaining));
                        truncated = true;
                        await reader.cancel();
                        break;
                    }
                    text += decoded;
                }
                if (!truncated) {
                    const tail = decoder.decode();
                    const remaining = limit - text.length;
                    text += tail.slice(0, Math.max(0, remaining));
                    truncated = tail.length > remaining;
                }
                return {text: text, truncated: truncated};
            }
            
            const originalFetch = window.fetch;
            window.fetch = async function(...args) {
                const rawUrl = typeof args[0] === 'string'
                    ? args[0] : (args[0] && args[0].url ? args[0].url : '');
                const requestUrl = absoluteURL(rawUrl);
                const method = ((args[1] && args[1].method)
                    || (args[0] && args[0].method) || 'GET').toUpperCase();

                let rawReqBody = '';
                if (args[1] && args[1].body) {
                    if (typeof args[1].body === 'string') {
                        rawReqBody = args[1].body;
                    } else {
                        rawReqBody = '[Binary/FormData]';
                    }
                }
                const reqBody = boundedText(rawReqBody, MAX_REQUEST_CHARS);

                let reqHeaders = {};
                const suppliedHeaders = (args[1] && args[1].headers)
                    || (args[0] && args[0].headers);
                if (suppliedHeaders) {
                    let h = suppliedHeaders;
                    if (h instanceof Headers) {
                        h.forEach((v, k) => reqHeaders[k] = v);
                    } else if (Array.isArray(h)) {
                        h.forEach(pair => { if (pair.length === 2) reqHeaders[pair[0]] = pair[1]; });
                    } else if (typeof h === 'object') {
                        reqHeaders = {...h};
                    }
                }

                const captureActive = window._sndNetworkCaptureEnabled === true;
                const captureContext = currentCaptureContext();
                if (captureActive) postNetworkActivity(captureContext, 'start');
                try {
                    const response = await originalFetch.apply(this, args);
                    if (!captureActive) return response;
                    let clone;
                    try {
                        clone = response.clone();
                    } catch (_) {
                        postNetworkActivity(captureContext, 'end');
                        return response;
                    }
                    readBoundedResponse(clone, MAX_RESPONSE_CHARS)
                        .then(captured => {
                            if (!captureStillCurrent(captureContext)) return;
                            window.webkit.messageHandlers.sndRecordingBridge.postMessage({
                                action: 'network_capture',
                                persona_id: captureContext.persona_id,
                                capture_session: captureContext.capture_session,
                                type: 'fetch',
                                url: requestUrl,
                                method: method,
                                request_headers: reqHeaders,
                                request_body: reqBody.text,
                                request_truncated: reqBody.truncated,
                                response_status: response.status,
                                response_body: captured.text,
                                response_truncated: captured.truncated
                            });
                        })
                        .catch(() => {
                            if (!captureStillCurrent(captureContext)) return;
                            window.webkit.messageHandlers.sndRecordingBridge.postMessage({
                                action: 'network_capture',
                                persona_id: captureContext.persona_id,
                                capture_session: captureContext.capture_session,
                                type: 'fetch',
                                url: requestUrl,
                                method: method,
                                request_headers: reqHeaders,
                                request_body: reqBody.text,
                                request_truncated: reqBody.truncated,
                                response_status: response.status,
                                response_body: '[Error reading response]',
                                response_truncated: false
                            });
                        })
                        .finally(() => postNetworkActivity(captureContext, 'end'));
                    return response;
                } catch (err) {
                    if (captureActive) postNetworkActivity(captureContext, 'end');
                    throw err;
                }
            };
            
            const originalXHR = window.XMLHttpRequest.prototype.open;
            const originalXHRSend = window.XMLHttpRequest.prototype.send;
            
            const originalXHRSetRequestHeader = window.XMLHttpRequest.prototype.setRequestHeader;
            
            window.XMLHttpRequest.prototype.open = function(method, url) {
                this._sndUrl = url;
                this._sndMethod = method;
                this._sndReqHeaders = {};
                return originalXHR.apply(this, arguments);
            };
            
            window.XMLHttpRequest.prototype.setRequestHeader = function(header, value) {
                if (!this._sndReqHeaders) this._sndReqHeaders = {};
                this._sndReqHeaders[header] = value;
                return originalXHRSetRequestHeader.apply(this, arguments);
            };
            
            window.XMLHttpRequest.prototype.send = function(body) {
                const rawReqBody = typeof body === 'string' ? body : '[Binary/FormData]';
                const reqBody = boundedText(rawReqBody, MAX_REQUEST_CHARS);
                const requestUrl = absoluteURL(this._sndUrl || '');
                const captureActive = window._sndNetworkCaptureEnabled === true;
                const captureContext = currentCaptureContext();
                if (captureActive) postNetworkActivity(captureContext, 'start');

                this.addEventListener('load', function() {
                    if (!captureActive || !captureStillCurrent(captureContext)) return;
                    let rawResBody = '';
                    if (this.responseType === '' || this.responseType === 'text') {
                        rawResBody = this.responseText;
                    } else {
                        rawResBody = '[Binary]';
                    }
                    const resBody = boundedText(rawResBody, MAX_RESPONSE_CHARS);
                    
                    window.webkit.messageHandlers.sndRecordingBridge.postMessage({
                        action: 'network_capture',
                        persona_id: captureContext.persona_id,
                        capture_session: captureContext.capture_session,
                        type: 'xhr',
                        url: requestUrl,
                        method: this._sndMethod || 'GET',
                        request_headers: this._sndReqHeaders || {},
                        request_body: reqBody.text,
                        request_truncated: reqBody.truncated,
                        response_status: this.status,
                        response_body: resBody.text,
                        response_truncated: resBody.truncated
                    });
                });
                this.addEventListener('loadend', function() {
                    if (captureActive) postNetworkActivity(captureContext, 'end');
                }, {once: true});
                try {
                    return originalXHRSend.apply(this, arguments);
                } catch (err) {
                    if (captureActive) postNetworkActivity(captureContext, 'end');
                    throw err;
                }
            };
        })();
        """
        
        let script = WKUserScript(source: js, injectionTime: .atDocumentStart, forMainFrameOnly: false)
        webView.configuration.userContentController.addUserScript(script)
        networkCaptureScriptCount += 1
    }

    public func stopNetworkCapture() async throws {
        networkCaptureEnabled = false
        networkCaptureOrigin = nil
        _ = try await webView.evaluateJavaScript("window._sndNetworkCaptureEnabled = false;")
    }

    public func scriptResourceURLs() async throws -> [String] {
        let js = """
        (() => {
            const raw = [
                ...Array.from(document.scripts || []).map(s => s.src),
                ...performance.getEntriesByType('resource')
                    .filter(e => e.initiatorType === 'script')
                    .map(e => e.name)
            ];
            const urls = [];
            const seen = new Set();
            for (const value of raw) {
                if (!value) continue;
                try {
                    const absolute = new URL(value, document.baseURI).href;
                    if (!seen.has(absolute)) {
                        seen.add(absolute);
                        urls.push(absolute);
                    }
                } catch (_) {}
                if (urls.length >= 64) break;
            }
            return urls;
        })();
        """
        let value = try await webView.evaluateJavaScript(js)
        return value as? [String] ?? []
    }
    
    public func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        if message.name == "sndRecordingBridge", let dict = message.body as? [String: Any] {
            // Forward back to python backend
            DriverBridgeClient.shared.sendSpontaneousEvent(event: "recorded_action", payload: ["action": dict])
        }
    }
}
