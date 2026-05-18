import XCTest
@testable import UltraLockedFormat

final class BundleLimitsTests: XCTestCase {

    // MARK: Argon2 bounds

    func testArgon2InRangeAccepted() throws {
        XCTAssertNoThrow(try BundleLimits.validateArgon2Params(timeCost: 3, memoryKiB: 65536, parallelism: 4))
        XCTAssertNoThrow(try BundleLimits.validateArgon2Params(timeCost: 1, memoryKiB: 8, parallelism: 1))
        XCTAssertNoThrow(try BundleLimits.validateArgon2Params(timeCost: 10, memoryKiB: 262144, parallelism: 8))
    }

    func testArgon2TimeCostExceedsMax() {
        XCTAssertThrowsError(try BundleLimits.validateArgon2Params(timeCost: 11, memoryKiB: 65536, parallelism: 4)) { error in
            guard case .parameterOutOfBounds = error as? BundleError else {
                XCTFail("expected parameterOutOfBounds")
                return
            }
        }
    }

    func testArgon2TimeCostBelowMin() {
        XCTAssertThrowsError(try BundleLimits.validateArgon2Params(timeCost: 0, memoryKiB: 65536, parallelism: 4))
    }

    func testArgon2MemoryExceedsMax() {
        // 256 MiB is the cap; 262145 KiB > 262144 KiB
        XCTAssertThrowsError(try BundleLimits.validateArgon2Params(timeCost: 3, memoryKiB: 262145, parallelism: 4))
    }

    func testArgon2MemoryBelowMin() {
        XCTAssertThrowsError(try BundleLimits.validateArgon2Params(timeCost: 3, memoryKiB: 7, parallelism: 4))
    }

    func testArgon2ParallelismExceedsMax() {
        XCTAssertThrowsError(try BundleLimits.validateArgon2Params(timeCost: 3, memoryKiB: 65536, parallelism: 9))
    }

    func testArgon2ParallelismBelowMin() {
        XCTAssertThrowsError(try BundleLimits.validateArgon2Params(timeCost: 3, memoryKiB: 65536, parallelism: 0))
    }

    // MARK: Manifest size

    func testManifestSizeAtMax() throws {
        XCTAssertNoThrow(try BundleLimits.validateManifestSize(BundleLimits.manifestSizeMax))
    }

    func testManifestSizeAboveMax() {
        XCTAssertThrowsError(try BundleLimits.validateManifestSize(BundleLimits.manifestSizeMax + 1))
    }

    // MARK: Item size

    func testItemSizeAtMax() throws {
        XCTAssertNoThrow(try BundleLimits.validateItemSize(BundleLimits.itemSizeMax))
    }

    func testItemSizeAboveMax() {
        XCTAssertThrowsError(try BundleLimits.validateItemSize(BundleLimits.itemSizeMax + 1))
    }

    // MARK: Total file size

    func testTotalFileSizeAtMax() throws {
        XCTAssertNoThrow(try BundleLimits.validateTotalFileSize(BundleLimits.totalFileSizeMax))
    }

    func testTotalFileSizeAboveMax() {
        XCTAssertThrowsError(try BundleLimits.validateTotalFileSize(BundleLimits.totalFileSizeMax + 1))
    }

    // MARK: Documented constants — protect against silent regressions

    func testDocumentedConstants() {
        XCTAssertEqual(BundleLimits.argon2TimeCostMax, 10)
        XCTAssertEqual(BundleLimits.argon2MemoryKiBMax, 262144)
        XCTAssertEqual(BundleLimits.argon2ParallelismMax, 8)
        XCTAssertEqual(BundleLimits.manifestSizeMax, 1 * 1024 * 1024)
        XCTAssertEqual(BundleLimits.itemSizeMax, 250 * 1024 * 1024)
        XCTAssertEqual(BundleLimits.totalFileSizeMax, 2 * 1024 * 1024 * 1024)
    }
}
