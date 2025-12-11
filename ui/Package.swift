// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SentinelUI",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "SentinelUI", targets: ["SentinelUI"])
    ],
    targets: [
        .executableTarget(
            name: "SentinelUI",
            path: "Sources",
            resources: [
                .copy("SentinelForgeUI/Resources")
            ]
        )
    ]
)
