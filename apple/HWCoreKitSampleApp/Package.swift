// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "HWCoreKitSampleApp",
    platforms: [
        .macOS(.v14),
    ],
    dependencies: [
        .package(path: "../HWCoreKit"),
    ],
    targets: [
        .executableTarget(
            name: "HWCoreKitSampleApp",
            dependencies: [
                .product(name: "HWCoreKit", package: "HWCoreKit"),
            ],
            linkerSettings: [
                .unsafeFlags([
                    "-Xlinker",
                    "-sectcreate",
                    "-Xlinker",
                    "__TEXT",
                    "-Xlinker",
                    "__info_plist",
                    "-Xlinker",
                    "Support/Info.plist",
                ]),
            ]
        ),
    ]
)
