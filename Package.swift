// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "LWIP",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
        .tvOS(.v13),
        .watchOS(.v6),
    ],
    products: [
        .library(
            name: "LWIP",
            targets: ["LWIP"]
        ),
    ],
    targets: [
        .target(
            name: "LWIP",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .testTarget(
            name: "LWIPTests",
            dependencies: ["LWIP"],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)
