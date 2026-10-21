// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "HWCoreKit",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
    ],
    products: [
        .library(name: "HWCoreKit", targets: ["HWCoreKit"]),
    ],
    targets: [
        .binaryTarget(name: "libhwcore", path: "HWCore.xcframework"),
        .target(
            name: "HWCoreFFI",
            dependencies: ["libhwcore"],
            path: "Sources/HWCoreFFI"
        ),
        .target(
            name: "HWCoreKit",
            dependencies: ["HWCoreFFI"],
            path: "Sources/HWCoreKit",
            linkerSettings: [
                .linkedFramework("CoreBluetooth"),
                .linkedFramework("Foundation"),
                .linkedLibrary("iconv"),
            ]
        ),
        .testTarget(
            name: "HWCoreKitTests",
            dependencies: ["HWCoreKit"],
            path: "Tests/HWCoreKitTests"
        ),
    ]
)
