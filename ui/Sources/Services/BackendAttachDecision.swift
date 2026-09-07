/// A listening core is not necessarily authenticated and ready for attachment.
enum ExternalCoreProbe: Equatable {
    case ready
    case presentNotReady
    case absent
}

enum BackendAttachAction: Equatable {
    case attach
    case spawn
    case wait
}

func classifyProbe(statusCode: Int?, healthStatus: String?, transportFailed: Bool)
    -> ExternalCoreProbe
{
    guard !transportFailed, let statusCode else { return .absent }
    if statusCode == 200, healthStatus == "ready" {
        return .ready
    }
    // Any HTTP response proves a listener is present, including 401/403.
    // Unknown responses must not cause the app to spawn a competing core.
    return .presentNotReady
}

func attachAction(for probe: ExternalCoreProbe, allowExternalBackend: Bool)
    -> BackendAttachAction
{
    switch probe {
    case .ready:
        return .attach
    case .presentNotReady:
        return .wait
    case .absent:
        return allowExternalBackend ? .wait : .spawn
    }
}
