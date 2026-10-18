import Foundation

enum GhostJavaScript {
    static func stringLiteral(_ value: String) throws -> String {
        String(decoding: try JSONEncoder().encode(value), as: UTF8.self)
    }

    static func selector(_ selector: [String: String]) throws -> String {
        let value = try stringLiteral(selector["value"] ?? "")

        switch selector["by"] ?? "" {
        case "css":
            return "document.querySelector(\(value))"
        case "name":
            return "document.getElementsByName(\(value)).item(0)"
        case "placeholder":
            return "Array.from(document.querySelectorAll('input,textarea')).find(el => el.placeholder === \(value))"
        case "text":
            return """
            Array.from(document.querySelectorAll('*')).reverse().find(el => {
                if (el.textContent.trim() !== \(value)) return false;
                let rect = el.getBoundingClientRect();
                return rect.width > 0 && rect.height > 0;
            })
            """
        default:
            return "document.querySelector(\(value))"
        }
    }
}
