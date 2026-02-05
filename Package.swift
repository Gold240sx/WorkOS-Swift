// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "WorkOSAuthKitSwift",
    platforms: [
        .iOS(.v16),
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "WorkOSAuthKitSwift",
            targets: ["WorkOSAuthKitSwift"]
        )
    ],
    dependencies: [],
    targets: [
        .target(
            name: "WorkOSAuthKitSwift",
            dependencies: [],
            path: "Sources/WorkOSAuthKitSwift"
        ),
        .testTarget(
            name: "WorkOSAuthKitSwiftTests",
            dependencies: ["WorkOSAuthKitSwift"],
            path: "Tests"
        )
    ]
)
