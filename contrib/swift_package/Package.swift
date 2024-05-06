// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "LibtelioSwift",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15)
    ],
    products: [
        .library(
            name: "LibtelioSwift",
            targets: ["LibtelioSwift", "telioFFI"]),
        .library(
            name: "sqlite3",
            targets: ["sqlite3"]),
    ],
    targets: [
        .target(
            name: "LibtelioSwift",
            dependencies: [
                "telioFFI"
            ],
            path: "Sources"
            ),
        .binaryTarget(
            name: "telioFFI",
            url: "$XCFRAMEWORK_URL",
            checksum: "$XCFRAMEWORK_CHECKSUM"
        ),
        .binaryTarget(
            name: "sqlite3",
            url: "$APPLE_SQLITE3_URL",
            checksum: "$APPLE_SQLITE3_CHECKSUM"
        )
    ]
)
