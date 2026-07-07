import Foundation

let session = URLSession(configuration: .default)
let url = URL(string: "ws://127.0.0.1:8765/v1/driver/bridge")!
let task = session.webSocketTask(with: url)

task.resume()

task.receive { result in
    switch result {
    case .success(let message):
        print("Success: \(message)")
    case .failure(let error):
        print("Failure: \(error)")
    }
    exit(0)
}

RunLoop.main.run(until: Date(timeIntervalSinceNow: 5))
