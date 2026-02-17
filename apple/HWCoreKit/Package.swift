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
        .systemLibrary(
            name: "libhwcore",
            path: "Sources/libhwcore"
        ),
        .target(
            name: "HWCoreFFI",
            dependencies: ["libhwcore"],
            path: "Sources/HWCoreFFI",
            linkerSettings: [
                .unsafeFlags(["-L", "../../target/debug", "-lhw_ffi"], .when(platforms: [.macOS])),
                .unsafeFlags(["-L", "../../target/ios-sim/debug", "-lhw_ffi"], .when(platforms: [.iOS])),
            ]
        ),
        .target(
            name: "HWCoreKit",
            dependencies: ["HWCoreFFI"],
            path: "Sources/HWCoreKit"
        ),
    ]
)
