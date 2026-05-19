import XCTest
@testable import UltraLockedFormat

final class BundleHeaderTests: XCTestCase {

    private func validHeader(
        timeCost: UInt32 = 3,
        memoryKiB: UInt32 = 65536,
        parallelism: UInt8 = 4,
        manifestSize: UInt32 = 1024
    ) throws -> BundleHeader {
        try BundleHeader(
            argon2TimeCost: timeCost,
            argon2MemoryKiB: memoryKiB,
            argon2Parallelism: parallelism,
            salt: Data(repeating: 0xAB, count: 16),
            manifestNonce: Data(repeating: 0xCD, count: 12),
            manifestSize: manifestSize
        )
    }

    func testRoundtrip() throws {
        let header = try validHeader()
        let serialized = header.serialize()
        XCTAssertEqual(serialized.count, BundleHeader.totalSize)
        let parsed = try BundleHeader.parse(serialized)
        XCTAssertEqual(parsed, header)
    }

    func testKnownByteLayout() throws {
        // All values within BundleLimits so the constructor accepts them, but chosen
        // to be distinctive enough to verify byte order and field offsets.
        let header = try BundleHeader(
            argon2TimeCost: 0x07,             // 7 iterations
            argon2MemoryKiB: 0x00010000,      // 65536 KiB
            argon2Parallelism: 8,
            salt: Data(repeating: 0xAA, count: 16),
            manifestNonce: Data(repeating: 0xBB, count: 12),
            manifestSize: 0x000A0000          // 655360 bytes (within 1 MiB cap)
        )
        let bytes = header.serialize()

        // magic
        XCTAssertEqual(Array(bytes[0..<8]), [0x55, 0x4C, 0x4F, 0x43, 0x4B, 0x45, 0x44, 0x31])
        // version (1, little-endian)
        XCTAssertEqual(Array(bytes[8..<10]), [0x01, 0x00])
        // kdf_id
        XCTAssertEqual(bytes[10], 0x01)
        // argon2_time_cost (7, little-endian)
        XCTAssertEqual(Array(bytes[11..<15]), [0x07, 0x00, 0x00, 0x00])
        // argon2_memory_kib (65536, little-endian)
        XCTAssertEqual(Array(bytes[15..<19]), [0x00, 0x00, 0x01, 0x00])
        // argon2_parallelism
        XCTAssertEqual(bytes[19], 0x08)
        // salt
        XCTAssertEqual(Array(bytes[20..<36]), Array(repeating: 0xAA, count: 16))
        // manifest_nonce
        XCTAssertEqual(Array(bytes[36..<48]), Array(repeating: 0xBB, count: 12))
        // manifest_size (655360, little-endian)
        XCTAssertEqual(Array(bytes[48..<52]), [0x00, 0x00, 0x0A, 0x00])
        // reserved padding (44 bytes of zero)
        XCTAssertEqual(Array(bytes[52..<96]), Array(repeating: 0x00, count: 44))
        XCTAssertEqual(bytes.count, 96)
    }

    func testTruncatedRejected() throws {
        let short = Data(repeating: 0, count: BundleHeader.totalSize - 1)
        XCTAssertThrowsError(try BundleHeader.parse(short)) { error in
            XCTAssertEqual(error as? BundleError, .truncated(expected: 96, actual: 95))
        }
    }

    func testMagicMismatchRejected() throws {
        let header = try validHeader()
        var bytes = header.serialize()
        bytes[0] = 0x00 // corrupt magic
        XCTAssertThrowsError(try BundleHeader.parse(bytes)) { error in
            guard case .invalidHeader = error as? BundleError else {
                XCTFail("expected invalidHeader, got \(error)")
                return
            }
        }
    }

    func testWrongVersionRejected() throws {
        let header = try validHeader()
        var bytes = header.serialize()
        bytes[8] = 99 // version low byte
        XCTAssertThrowsError(try BundleHeader.parse(bytes)) { error in
            XCTAssertEqual(error as? BundleError, .unsupportedVersion(99))
        }
    }

    func testWrongKDFRejected() throws {
        let header = try validHeader()
        var bytes = header.serialize()
        bytes[10] = 99 // kdf_id
        XCTAssertThrowsError(try BundleHeader.parse(bytes)) { error in
            XCTAssertEqual(error as? BundleError, .unsupportedKDF(99))
        }
    }

    func testManifestSizeBelowMinimumRejected() throws {
        XCTAssertThrowsError(try validHeader(manifestSize: BundleLimits.manifestSizeMin - 1)) { error in
            guard case .parameterOutOfBounds = error as? BundleError else {
                XCTFail("expected parameterOutOfBounds, got \(error)")
                return
            }
        }
    }

    func testReservedBytesMustBeZero() throws {
        let header = try validHeader()
        var bytes = header.serialize()
        bytes[52] = 0x01
        XCTAssertThrowsError(try BundleHeader.parse(bytes)) { error in
            guard case .invalidHeader = error as? BundleError else {
                XCTFail("expected invalidHeader, got \(error)")
                return
            }
        }
    }

    func testInvalidSaltSizeRejected() throws {
        XCTAssertThrowsError(try BundleHeader(
            argon2TimeCost: 3,
            argon2MemoryKiB: 65536,
            argon2Parallelism: 4,
            salt: Data(repeating: 0xAB, count: 8), // wrong size
            manifestNonce: Data(repeating: 0xCD, count: 12),
            manifestSize: 1024
        )) { error in
            guard case .invalidHeader = error as? BundleError else {
                XCTFail("expected invalidHeader, got \(error)")
                return
            }
        }
    }

    func testInvalidNonceSizeRejected() throws {
        XCTAssertThrowsError(try BundleHeader(
            argon2TimeCost: 3,
            argon2MemoryKiB: 65536,
            argon2Parallelism: 4,
            salt: Data(repeating: 0xAB, count: 16),
            manifestNonce: Data(repeating: 0xCD, count: 8), // wrong size
            manifestSize: 1024
        )) { error in
            guard case .invalidHeader = error as? BundleError else {
                XCTFail("expected invalidHeader, got \(error)")
                return
            }
        }
    }

    func testParserRejectsArgon2OutOfBounds() throws {
        let header = try validHeader()
        var bytes = header.serialize()
        // Write argon2.time_cost = 99 (> max 10)
        bytes[11] = 99; bytes[12] = 0; bytes[13] = 0; bytes[14] = 0
        XCTAssertThrowsError(try BundleHeader.parse(bytes)) { error in
            guard case .parameterOutOfBounds = error as? BundleError else {
                XCTFail("expected parameterOutOfBounds, got \(error)")
                return
            }
        }
    }

    func testParserAcceptsTrailingDataBeyondHeader() throws {
        // Real bundles will have ciphertext after the header. parse() should accept
        // the prefix.
        let header = try validHeader()
        var bytes = header.serialize()
        bytes.append(Data(repeating: 0xFF, count: 1000)) // trailing manifest+items
        let parsed = try BundleHeader.parse(bytes)
        XCTAssertEqual(parsed, header)
    }
}
