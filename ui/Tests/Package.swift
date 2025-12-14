// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "TestRunner",
    platforms: [.macOS(.v13)],
    dependencies: [
        .package(path: "../ui") // Link against the main UI package
    ],
    targets: [
        .executableTarget(
            name: "TestRunner",
            dependencies: [
                .product(name: "SentinelForgeUI", package: "ui")
            ]
        )
    ]
)
