import XCTest
import CryptoKit
@testable import UltraLockedFormat

/// End-to-end Builder + Parser roundtrip tests using a pre-derived master key
/// (so they don't depend on libargon2 being integrated yet).
final class BundleRoundtripTests: XCTestCase {

    private func fixedMasterKey() -> SymmetricKey {
        SymmetricKey(data: Data(repeating: 0x42, count: 32))
    }

    private func fixedSalt() -> Data {
        Data(repeating: 0xAB, count: 16)
    }

    private func fixedManifestNonce() -> Data {
        Data(repeating: 0xCD, count: 12)
    }

    private func makeContent(
        name: String,
        mimeType: String = "application/octet-stream",
        bytes: Data,
        ttl: UInt64? = nil,
        ttlOrigin: Date? = nil
    ) -> ItemContent {
        ItemContent(
            id: UUID(),
            name: name,
            mimeType: mimeType,
            plaintext: bytes,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_000),
            ttlSeconds: ttl,
            ttlOriginEpoch: ttlOrigin
        )
    }

    private func builder(label: String? = "test") -> BundleBuilder {
        BundleBuilder(
            parameters: .recommendedDefault,
            exportLabel: label,
            exportedAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
    }

    // MARK: Empty bundle

    func testEmptyBundleRoundtrip() throws {
        let b = builder()
        let bytes = try b.build(masterKey: fixedMasterKey(), salt: fixedSalt(), manifestNonce: fixedManifestNonce())
        XCTAssertGreaterThanOrEqual(bytes.count, BundleHeader.totalSize)

        let parser = try BundleParser(data: bytes)
        let manifest = try parser.unlock(masterKey: fixedMasterKey())
        XCTAssertEqual(manifest.items.count, 0)
        XCTAssertEqual(manifest.exportLabel, "test")
    }

    // MARK: Single item

    func testSingleItemRoundtrip() throws {
        let plaintext = Data("the quick brown fox".utf8)
        let content = makeContent(name: "fox.txt", mimeType: "text/plain", bytes: plaintext)

        let b = builder()
        b.add(content)
        let bytes = try b.build(masterKey: fixedMasterKey(), salt: fixedSalt(), manifestNonce: fixedManifestNonce())

        let parser = try BundleParser(data: bytes)
        let manifest = try parser.unlock(masterKey: fixedMasterKey())
        XCTAssertEqual(manifest.items.count, 1)
        XCTAssertEqual(manifest.items[0].name, "fox.txt")
        XCTAssertEqual(manifest.items[0].mimeType, "text/plain")
        XCTAssertEqual(manifest.items[0].sizeBytes, UInt64(plaintext.count))

        let decrypted = try parser.decrypt(item: manifest.items[0])
        XCTAssertEqual(decrypted, plaintext)
    }

    func testDecryptUsesCanonicalManifestDescriptor() throws {
        let plaintext = Data("canonical descriptor wins".utf8)
        let content = makeContent(name: "canonical.txt", mimeType: "text/plain", bytes: plaintext)

        let b = builder()
        b.add(content)
        let bytes = try b.build(masterKey: fixedMasterKey(), salt: fixedSalt(), manifestNonce: fixedManifestNonce())

        let parser = try BundleParser(data: bytes)
        let manifest = try parser.unlock(masterKey: fixedMasterKey())
        let descriptor = manifest.items[0]
        let callerSuppliedDescriptor = try ItemDescriptor(
            id: descriptor.id,
            name: descriptor.name,
            mimeType: descriptor.mimeType,
            sizeBytes: descriptor.sizeBytes,
            createdAt: descriptor.createdAt,
            modifiedAt: descriptor.modifiedAt,
            ttlSeconds: descriptor.ttlSeconds,
            ttlOriginEpoch: descriptor.ttlOriginEpoch,
            itemNonce: Data(repeating: 0xEE, count: 12),
            itemSize: BundleLimits.itemSizeMin
        )

        XCTAssertEqual(try parser.decrypt(item: callerSuppliedDescriptor), plaintext)
    }

    // MARK: Multiple items

    func testMultipleItemsRoundtripPreservesOrder() throws {
        let p1 = Data("one".utf8)
        let p2 = Data("two".utf8)
        let p3 = Data("three".utf8)
        let c1 = makeContent(name: "1.txt", bytes: p1)
        let c2 = makeContent(name: "2.txt", bytes: p2)
        let c3 = makeContent(name: "3.txt", bytes: p3)

        let b = builder()
        b.add(c1); b.add(c2); b.add(c3)
        let bytes = try b.build(masterKey: fixedMasterKey(), salt: fixedSalt(), manifestNonce: fixedManifestNonce())

        let parser = try BundleParser(data: bytes)
        let manifest = try parser.unlock(masterKey: fixedMasterKey())

        XCTAssertEqual(manifest.items.map(\.id), [c1.id, c2.id, c3.id])
        XCTAssertEqual(try parser.decrypt(item: manifest.items[0]), p1)
        XCTAssertEqual(try parser.decrypt(item: manifest.items[1]), p2)
        XCTAssertEqual(try parser.decrypt(item: manifest.items[2]), p3)
    }

    // MARK: Item types and sizes

    func testEmptyItemPlaintextRoundtrip() throws {
        let c = makeContent(name: "empty", bytes: Data())
        let b = builder()
        b.add(c)
        let bytes = try b.build(masterKey: fixedMasterKey(), salt: fixedSalt(), manifestNonce: fixedManifestNonce())
        let parser = try BundleParser(data: bytes)
        let manifest = try parser.unlock(masterKey: fixedMasterKey())
        XCTAssertEqual(try parser.decrypt(item: manifest.items[0]), Data())
    }

    func testLargishItemRoundtrip() throws {
        // 1 MiB item — well within itemSizeMax (250 MiB) but exercises the streaming path.
        let large = Data(repeating: 0x55, count: 1024 * 1024)
        let c = makeContent(name: "big.bin", bytes: large)
        let b = builder()
        b.add(c)
        let bytes = try b.build(masterKey: fixedMasterKey(), salt: fixedSalt(), manifestNonce: fixedManifestNonce())
        let parser = try BundleParser(data: bytes)
        let manifest = try parser.unlock(masterKey: fixedMasterKey())
        XCTAssertEqual(try parser.decrypt(item: manifest.items[0]), large)
    }

    // MARK: TTL preservation

    func testTTLFieldsRoundtrip() throws {
        let origin = Date(timeIntervalSince1970: 1_700_000_000)
        let c = makeContent(name: "expiring", bytes: Data("secret".utf8), ttl: 3600, ttlOrigin: origin)
        let b = builder()
        b.add(c)
        let bytes = try b.build(masterKey: fixedMasterKey(), salt: fixedSalt(), manifestNonce: fixedManifestNonce())
        let parser = try BundleParser(data: bytes)
        let manifest = try parser.unlock(masterKey: fixedMasterKey())
        XCTAssertEqual(manifest.items[0].ttlSeconds, 3600)
        XCTAssertEqual(manifest.items[0].ttlOriginEpoch, origin)
    }

    // MARK: Parse-without-unlock UX

    func testHeaderAvailableBeforeUnlock() throws {
        let c = makeContent(name: "x", bytes: Data("hello".utf8))
        let b = builder(label: "iPhone backup")
        b.add(c)
        let bytes = try b.build(masterKey: fixedMasterKey(), salt: fixedSalt(), manifestNonce: fixedManifestNonce())

        let parser = try BundleParser(data: bytes)
        // No unlock yet — header info is available, but manifest isn't.
        XCTAssertEqual(parser.header.salt, fixedSalt())
        XCTAssertEqual(parser.header.manifestNonce, fixedManifestNonce())
        XCTAssertEqual(parser.header.argon2TimeCost, Argon2idParameters.recommendedDefault.timeCost)
        XCTAssertGreaterThan(parser.header.manifestSize, 0)
    }

    func testDecryptBeforeUnlockFails() throws {
        let c = makeContent(name: "x", bytes: Data("hello".utf8))
        let b = builder()
        b.add(c)
        let bytes = try b.build(masterKey: fixedMasterKey(), salt: fixedSalt(), manifestNonce: fixedManifestNonce())
        let parser = try BundleParser(data: bytes)
        // Build a fake descriptor so we can call decrypt(item:) without unlocking.
        let descriptor = try ItemDescriptor(
            id: c.id, name: "x", mimeType: "application/octet-stream",
            sizeBytes: 5,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_000),
            ttlSeconds: nil, ttlOriginEpoch: nil,
            itemNonce: Data(repeating: 0, count: 12), itemSize: 21
        )
        XCTAssertThrowsError(try parser.decrypt(item: descriptor))
    }

    // MARK: Tamper detection

    func testTamperedHeaderIsRejected() throws {
        let c = makeContent(name: "x", bytes: Data("hello".utf8))
        let b = builder()
        b.add(c)
        var bytes = try b.build(masterKey: fixedMasterKey(), salt: fixedSalt(), manifestNonce: fixedManifestNonce())
        // Flip a byte inside the salt region (offset 20..36 in the header).
        bytes[25] ^= 0xFF
        // The header still parses (salt format is opaque), but unlock fails: header bytes
        // form the AAD for the manifest, so the manifest tag is invalid.
        let parser = try BundleParser(data: bytes)
        XCTAssertThrowsError(try parser.unlock(masterKey: fixedMasterKey())) { error in
            XCTAssertEqual(error as? BundleError, .decryptionFailed)
        }
    }

    func testTamperedManifestIsRejected() throws {
        let c = makeContent(name: "x", bytes: Data("hello".utf8))
        let b = builder()
        b.add(c)
        var bytes = try b.build(masterKey: fixedMasterKey(), salt: fixedSalt(), manifestNonce: fixedManifestNonce())
        // Manifest starts at offset 96.
        bytes[96] ^= 0xFF
        let parser = try BundleParser(data: bytes)
        XCTAssertThrowsError(try parser.unlock(masterKey: fixedMasterKey()))
    }

    func testTamperedItemIsRejected() throws {
        let p1 = Data("one".utf8)
        let p2 = Data("two".utf8)
        let c1 = makeContent(name: "1.txt", bytes: p1)
        let c2 = makeContent(name: "2.txt", bytes: p2)
        let b = builder()
        b.add(c1); b.add(c2)
        var bytes = try b.build(masterKey: fixedMasterKey(), salt: fixedSalt(), manifestNonce: fixedManifestNonce())

        // Parse first to learn item offsets, then tamper with item 2's first byte.
        let parser = try BundleParser(data: bytes)
        let manifest = try parser.unlock(masterKey: fixedMasterKey())
        let item1End = BundleHeader.totalSize + Int(parser.header.manifestSize) + Int(manifest.items[0].itemSize)
        bytes[item1End] ^= 0xFF

        let parser2 = try BundleParser(data: bytes)
        let manifest2 = try parser2.unlock(masterKey: fixedMasterKey())
        // Item 1 still decrypts cleanly.
        XCTAssertEqual(try parser2.decrypt(item: manifest2.items[0]), p1)
        // Item 2 fails because the auth tag is invalid.
        XCTAssertThrowsError(try parser2.decrypt(item: manifest2.items[1]))
    }

    func testWrongMasterKeyIsRejected() throws {
        let c = makeContent(name: "x", bytes: Data("hello".utf8))
        let b = builder()
        b.add(c)
        let bytes = try b.build(masterKey: fixedMasterKey(), salt: fixedSalt(), manifestNonce: fixedManifestNonce())
        let parser = try BundleParser(data: bytes)
        let wrong = SymmetricKey(data: Data(repeating: 0x99, count: 32))
        XCTAssertThrowsError(try parser.unlock(masterKey: wrong)) { error in
            XCTAssertEqual(error as? BundleError, .decryptionFailed)
        }
    }

    // MARK: Lock / unlock cycle

    func testLockClearsCachedKey() throws {
        let c = makeContent(name: "x", bytes: Data("hello".utf8))
        let b = builder()
        b.add(c)
        let bytes = try b.build(masterKey: fixedMasterKey(), salt: fixedSalt(), manifestNonce: fixedManifestNonce())
        let parser = try BundleParser(data: bytes)
        let manifest = try parser.unlock(masterKey: fixedMasterKey())
        XCTAssertEqual(try parser.decrypt(item: manifest.items[0]), Data("hello".utf8))
        parser.lock()
        XCTAssertThrowsError(try parser.decrypt(item: manifest.items[0]))
    }

    // MARK: Byte layout invariants

    func testTotalFileSizeMatchesHeaderAndItems() throws {
        let p1 = Data("one".utf8)
        let p2 = Data("two".utf8)
        let b = builder()
        b.add(makeContent(name: "1", bytes: p1))
        b.add(makeContent(name: "2", bytes: p2))
        let bytes = try b.build(masterKey: fixedMasterKey(), salt: fixedSalt(), manifestNonce: fixedManifestNonce())

        let parser = try BundleParser(data: bytes)
        let manifest = try parser.unlock(masterKey: fixedMasterKey())
        let expected = BundleHeader.totalSize
            + Int(parser.header.manifestSize)
            + manifest.items.reduce(0) { $0 + Int($1.itemSize) }
        XCTAssertEqual(bytes.count, expected)
    }
}
