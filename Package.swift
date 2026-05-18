// swift-tools-version:5.10
import PackageDescription

// Vendored dependency:
//
//   CArgon2 = libargon2 from https://github.com/P-H-C/phc-winner-argon2
//   Pinned to the 20190702 release tag (the latest tagged release of the official
//   Argon2 reference implementation by the Password Hashing Competition committee).
//   License: Apache-2.0 OR CC0-1.0 (dual-licensed). See Sources/CArgon2/LICENSE.
//
//   Files vendored from upstream:
//     include/argon2.h
//     src/argon2.c, core.c, core.h, encoding.c, encoding.h, ref.c, thread.c, thread.h
//     src/blake2/blake2b.c, blake2/blake2.h, blake2/blake2-impl.h
//
//   The optimized (SIMD) implementation `src/opt.c` is intentionally NOT vendored;
//   we use the portable reference implementation `src/ref.c` instead. Both define the
//   same `fill_segment` symbol, so including only one is required.
//
//   Threading is left enabled; pthread is available on iOS and macOS.

let package = Package(
    name: "UltraLockedFormat",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(name: "UltraLockedFormat", targets: ["UltraLockedFormat"]),
    ],
    targets: [
        .target(
            name: "CArgon2",
            path: "Sources/CArgon2",
            exclude: ["LICENSE"],
            publicHeadersPath: "include",
            cSettings: [
                .headerSearchPath("."),
                .headerSearchPath("blake2"),
            ]
        ),
        .target(
            name: "UltraLockedFormat",
            dependencies: ["CArgon2"],
            path: "Sources/UltraLockedFormat"
        ),
        .testTarget(
            name: "UltraLockedFormatTests",
            dependencies: ["UltraLockedFormat"],
            path: "Tests/UltraLockedFormatTests"
        ),
    ]
)
