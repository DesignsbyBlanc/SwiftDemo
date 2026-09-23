// swift-tools-version: 6.3

import PackageDescription

let package = Package(
    name: "SwiftDemo",
    targets: [
        .systemLibrary(
            name: "MinHook"
        ),

        .executableTarget(
            name: "SwiftDemo",
            dependencies: [
                "MinHook"
            ],
            linkerSettings: [
                .unsafeFlags([
                    "-LC:/stuff/SwiftDemo/vcpkg/packages/minhook_x64-windows/lib"
                ]),
                .linkedLibrary("kernel32"),
            ]
        ),

        .testTarget(
            name: "SwiftDemoTests",
            dependencies: [
                "SwiftDemo"
            ]
        ),
    ],
    swiftLanguageModes: [
        .v6
    ]
)
