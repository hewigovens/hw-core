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
        .target(
            name: "hw_ffiFFI",
            path: "Sources/hw_ffiFFI",
            publicHeadersPath: "."
        ),
        .target(
            name: "HWCoreKitBindings",
            dependencies: ["hw_ffiFFI"],
            path: "Sources/HWCoreKitBindings",
            linkerSettings: [
                .unsafeFlags(["-L", "../../target/debug", "-lhw_ffi"]),
            ]
        ),
        .target(
            name: "HWCoreKit",
            dependencies: ["HWCoreKitBindings"],
            path: "Sources/HWCoreKit"
        ),
    ]
)
