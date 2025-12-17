//
// PURPOSE:
// This Swift component is part of the SentinelForge macOS UI.
// [Specific purpose based on component name: Package]
//
// KEY RESPONSIBILITIES:
// - [Automatically generated - review and enhance based on actual functionality]
//
// INTEGRATION:
// - Used by: [To be documented]
// - Depends on: [To be documented]
//

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
