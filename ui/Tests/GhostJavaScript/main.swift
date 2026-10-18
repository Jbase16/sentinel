// Run with:
// xcrun swiftc ui/Sources/Core/GhostJavaScript.swift ui/Tests/GhostJavaScript/main.swift \
//   -framework JavaScriptCore -o /tmp/ghost-javascript-test && /tmp/ghost-javascript-test
import Foundation
import JavaScriptCore

let context = JSContext()!
let hostile = "x'); globalThis.pwned = true; ('</script>\"\\\nvalue"
let hostileAttribute = "data-x'); globalThis.pwned = true; ('</script>\"\\\n"
context.setObject(hostile, forKeyedSubscript: "expected" as NSString)
context.evaluateScript(
    """
    var pwned = false;
    var lastSelector = null;
    var lastAttribute = null;
    var element = {
        placeholder: expected,
        textContent: expected,
        getBoundingClientRect: () => ({width: 1, height: 1}),
        getAttribute: name => { lastAttribute = name; return 'attribute-value'; }
    };
    var document = {
        querySelector: value => { lastSelector = value; return element; },
        getElementsByName: value => {
            lastSelector = value;
            return {item: index => index === 0 ? element : null};
        },
        querySelectorAll: () => [element]
    };
    """
)

for by in ["css", "name", "placeholder", "text", "unknown"] {
    let script = try GhostJavaScript.selector(["by": by, "value": hostile])
    let result = context.evaluateScript(script)
    precondition(context.exception == nil, "selector script failed for \(by)")
    precondition(result?.isObject == true, "selector missed element for \(by)")
    precondition(context.evaluateScript("pwned")?.toBool() == false, "selector ran injected code")
    if by == "css" || by == "name" || by == "unknown" {
        precondition(context.evaluateScript("lastSelector")?.toString() == hostile)
    }
}

let selector = try GhostJavaScript.selector(["by": "css", "value": hostile])
let attribute = try GhostJavaScript.stringLiteral(hostileAttribute)
let result = context.evaluateScript("(\(selector)).getAttribute(\(attribute))")
precondition(context.exception == nil, "attribute script failed")
precondition(result?.toString() == "attribute-value")
precondition(context.evaluateScript("lastAttribute")?.toString() == hostileAttribute)
precondition(context.evaluateScript("pwned")?.toBool() == false, "attribute ran injected code")
print("Ghost JavaScript hostile selector and attribute tests passed")
