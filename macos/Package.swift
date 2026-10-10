// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "OpenPassMenu",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(
            name: "OpenPassMenu",
            path: "Sources/OpenPassMenu"
        ),
    ],
    swiftLanguageModes: [.v5]
)
