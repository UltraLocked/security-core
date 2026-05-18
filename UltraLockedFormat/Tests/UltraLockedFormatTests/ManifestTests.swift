import XCTest
import CryptoKit
@testable import UltraLockedFormat

final class ManifestTests: XCTestCase {

    // MARK: Fixtures

    private func makeItem(
        id: UUID = UUID(uuidString: "550E8400-E29B-41D4-A716-446655440000")!,
        name: String = "doc.rtf",
        mimeType: String = "application/rtf",
        sizeBytes: UInt64 = 1024,
        ttl: UInt64? = nil,
        ttlOrigin: Date? = nil,
        nonce: Data = Data(repeating: 0xAA, count: 12),
        itemSize: UInt64 = 1040
    ) throws -> ItemDescriptor {
        let date = Date(timeIntervalSince1970: 1_700_000_000)
        return try ItemDescriptor(
            id: id,
            name: name,
            mimeType: mimeType,
            sizeBytes: sizeBytes,
            createdAt: date,
            modifiedAt: date,
            ttlSeconds: ttl,
            ttlOriginEpoch: ttlOrigin,
            itemNonce: nonce,
            itemSize: itemSize
        )
    }

    private func fixedMasterKey() -> SymmetricKey {
        SymmetricKey(data: Data(repeating: 0x42, count: 32))
    }

    private func fixedManifestNonce() -> Data {
        Data(repeating: 0x33, count: 12)
    }

    private func fixedHeaderAAD() -> Data {
        Data(repeating: 0xCD, count: 96)
    }

    // MARK: ItemDescriptor validation

    func testItemDescriptorRejectsBadNonce() {
        XCTAssertThrowsError(try makeItem(nonce: Data(repeating: 0xAA, count: 8)))
    }

    func testItemDescriptorRejectsItemSizeOverMax() {
        XCTAssertThrowsError(try makeItem(itemSize: BundleLimits.itemSizeMax + 1))
    }

    func testItemDescriptorAcceptsItemSizeAtMax() {
        XCTAssertNoThrow(try makeItem(itemSize: BundleLimits.itemSizeMax))
    }

    func testItemDescriptorRejectsHalfTTL() {
        XCTAssertThrowsError(try makeItem(ttl: 100, ttlOrigin: nil))
        XCTAssertThrowsError(try makeItem(ttl: nil, ttlOrigin: Date()))
    }

    func testItemDescriptorAcceptsBothTTLOrNeither() throws {
        XCTAssertNoThrow(try makeItem(ttl: nil, ttlOrigin: nil))
        XCTAssertNoThrow(try makeItem(ttl: 3600, ttlOrigin: Date()))
    }

    // MARK: JSON roundtrip

    func testManifestJSONRoundtrip() throws {
        let item = try makeItem()
        let manifest = Manifest(
            exportedAt: Date(timeIntervalSince1970: 1_700_000_000),
            exportLabel: "iPhone backup",
            items: [item]
        )
        let json = try manifest.encodeJSON()
        let decoded = try Manifest.decodeJSON(json)
        XCTAssertEqual(decoded, manifest)
    }

    func testManifestJSONShape() throws {
        let item = try makeItem(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!,
            name: "doc.rtf",
            mimeType: "application/rtf",
            sizeBytes: 1024,
            ttl: 3600,
            ttlOrigin: Date(timeIntervalSince1970: 1_700_000_000),
            nonce: Data(repeating: 0x01, count: 12),
            itemSize: 1040
        )
        let manifest = Manifest(
            exportedAt: Date(timeIntervalSince1970: 1_700_000_000),
            exportLabel: "test",
            items: [item]
        )
        let json = try manifest.encodeJSON()
        let str = String(data: json, encoding: .utf8)!

        // snake_case keys
        XCTAssertTrue(str.contains("\"schema_version\":1"))
        XCTAssertTrue(str.contains("\"export_label\":\"test\""))
        XCTAssertTrue(str.contains("\"exported_at\""))
        XCTAssertTrue(str.contains("\"mime_type\":\"application\\/rtf\"") || str.contains("\"mime_type\":\"application/rtf\""))
        XCTAssertTrue(str.contains("\"size_bytes\":1024"))
        XCTAssertTrue(str.contains("\"ttl_seconds\":3600"))
        XCTAssertTrue(str.contains("\"ttl_origin_epoch\""))
        XCTAssertTrue(str.contains("\"item_nonce\""))
        XCTAssertTrue(str.contains("\"item_size\":1040"))
        XCTAssertTrue(str.contains("\"created_at\""))
        XCTAssertTrue(str.contains("\"modified_at\""))
    }

    func testManifestEncodingIsDeterministic() throws {
        let item = try makeItem()
        let manifest = Manifest(
            exportedAt: Date(timeIntervalSince1970: 1_700_000_000),
            exportLabel: "x",
            items: [item]
        )
        let bytes1 = try manifest.encodeJSON()
        let bytes2 = try manifest.encodeJSON()
        XCTAssertEqual(bytes1, bytes2)
    }

    func testManifestDecodeRejectsWrongSchemaVersion() throws {
        let item = try makeItem()
        let manifest = Manifest(
            exportedAt: Date(timeIntervalSince1970: 1_700_000_000),
            exportLabel: nil,
            items: [item]
        )
        var json = try manifest.encodeJSON()
        // Replace "schema_version":1 with "schema_version":99 (length unchanged)
        let str = String(data: json, encoding: .utf8)!
            .replacingOccurrences(of: "\"schema_version\":1", with: "\"schema_version\":9")
        json = str.data(using: .utf8)!
        XCTAssertThrowsError(try Manifest.decodeJSON(json)) { error in
            guard case .manifestParseFailed = error as? BundleError else {
                XCTFail("expected manifestParseFailed, got \(error)")
                return
            }
        }
    }

    func testManifestDecodeRejectsDuplicateItemIDs() throws {
        let id = UUID()
        let item1 = try makeItem(id: id, name: "a.rtf")
        let item2 = try makeItem(id: id, name: "b.rtf")
        let manifest = Manifest(items: [item1, item2])
        let json = try manifest.encodeJSON()
        XCTAssertThrowsError(try Manifest.decodeJSON(json)) { error in
            guard case .manifestParseFailed = error as? BundleError else {
                XCTFail("expected manifestParseFailed, got \(error)")
                return
            }
        }
    }

    func testManifestDecodeRejectsCorruptJSON() {
        let bad = Data("not json".utf8)
        XCTAssertThrowsError(try Manifest.decodeJSON(bad)) { error in
            guard case .manifestParseFailed = error as? BundleError else {
                XCTFail("expected manifestParseFailed, got \(error)")
                return
            }
        }
    }

    func testManifestDecodeRejectsItemWithBadNonce() throws {
        // Hand-craft JSON that has a manifest with an 8-byte item_nonce.
        let id = UUID()
        let badJSON = """
        {
          "schema_version": 1,
          "exported_at": "2026-04-28T00:00:00Z",
          "items": [
            {
              "id": "\(id.uuidString)",
              "name": "x",
              "mime_type": "application/octet-stream",
              "size_bytes": 0,
              "created_at": "2026-04-28T00:00:00Z",
              "modified_at": "2026-04-28T00:00:00Z",
              "ttl_seconds": null,
              "ttl_origin_epoch": null,
              "item_nonce": "\(Data(repeating: 0xAA, count: 8).base64EncodedString())",
              "item_size": 16
            }
          ]
        }
        """
        let data = Data(badJSON.utf8)
        XCTAssertThrowsError(try Manifest.decodeJSON(data)) { error in
            guard case .manifestParseFailed = error as? BundleError else {
                XCTFail("expected manifestParseFailed, got \(error)")
                return
            }
        }
    }

    // MARK: Encrypt / decrypt

    func testManifestEncryptDecryptRoundtrip() throws {
        let item = try makeItem()
        let manifest = Manifest(
            exportedAt: Date(timeIntervalSince1970: 1_700_000_000),
            exportLabel: "iPhone",
            items: [item]
        )
        let masterKey = fixedMasterKey()
        let nonce = fixedManifestNonce()
        let aad = fixedHeaderAAD()
        let (ciphertext, tag) = try manifest.encrypt(masterKey: masterKey, nonce: nonce, headerAAD: aad)
        let decrypted = try Manifest.decrypt(
            ciphertext: ciphertext,
            tag: tag,
            masterKey: masterKey,
            nonce: nonce,
            headerAAD: aad
        )
        XCTAssertEqual(decrypted, manifest)
    }

    func testManifestDecryptRejectsTamperedHeaderAAD() throws {
        let item = try makeItem()
        let manifest = Manifest(
            exportedAt: Date(timeIntervalSince1970: 1_700_000_000),
            items: [item]
        )
        let masterKey = fixedMasterKey()
        let nonce = fixedManifestNonce()
        let aad = fixedHeaderAAD()
        let (ciphertext, tag) = try manifest.encrypt(masterKey: masterKey, nonce: nonce, headerAAD: aad)
        var tamperedAAD = Data(aad)
        tamperedAAD[0] ^= 0xFF
        XCTAssertThrowsError(try Manifest.decrypt(
            ciphertext: ciphertext,
            tag: tag,
            masterKey: masterKey,
            nonce: nonce,
            headerAAD: tamperedAAD
        )) { error in
            XCTAssertEqual(error as? BundleError, .decryptionFailed)
        }
    }

    func testManifestDecryptRejectsTamperedCiphertext() throws {
        let item = try makeItem()
        let manifest = Manifest(
            exportedAt: Date(timeIntervalSince1970: 1_700_000_000),
            items: [item]
        )
        let masterKey = fixedMasterKey()
        let nonce = fixedManifestNonce()
        let aad = fixedHeaderAAD()
        let result = try manifest.encrypt(masterKey: masterKey, nonce: nonce, headerAAD: aad)
        var ciphertext = Data(result.ciphertext)
        ciphertext[0] ^= 0x01
        XCTAssertThrowsError(try Manifest.decrypt(
            ciphertext: ciphertext,
            tag: result.tag,
            masterKey: masterKey,
            nonce: nonce,
            headerAAD: aad
        ))
    }

    func testManifestDecryptRejectsWrongKey() throws {
        let item = try makeItem()
        let manifest = Manifest(
            exportedAt: Date(timeIntervalSince1970: 1_700_000_000),
            items: [item]
        )
        let masterKey = fixedMasterKey()
        let wrongKey = SymmetricKey(data: Data(repeating: 0x99, count: 32))
        let nonce = fixedManifestNonce()
        let aad = fixedHeaderAAD()
        let (ciphertext, tag) = try manifest.encrypt(masterKey: masterKey, nonce: nonce, headerAAD: aad)
        XCTAssertThrowsError(try Manifest.decrypt(
            ciphertext: ciphertext,
            tag: tag,
            masterKey: wrongKey,
            nonce: nonce,
            headerAAD: aad
        ))
    }

    func testManifestEncryptIntegratesWithBundleHeader() throws {
        // Wire it together: real BundleHeader bytes used as AAD; manifest_size is set
        // to the actual ciphertext + tag length. Verify roundtrip end-to-end.
        // exportedAt uses an integer-second Date so ISO-8601 roundtrip is lossless.
        let item = try makeItem()
        let manifest = Manifest(
            exportedAt: Date(timeIntervalSince1970: 1_700_000_000),
            exportLabel: nil,
            items: [item]
        )
        let masterKey = fixedMasterKey()
        let nonce = Data(repeating: 0x33, count: 12)
        let salt = Data(repeating: 0xAB, count: 16)

        // First-pass encryption to learn manifest_size
        let trial = try manifest.encrypt(masterKey: masterKey, nonce: nonce, headerAAD: Data(count: 96))
        let manifestSize = UInt32(trial.ciphertext.count + trial.tag.count)

        let header = try BundleHeader(
            argon2TimeCost: 3,
            argon2MemoryKiB: 65536,
            argon2Parallelism: 4,
            salt: salt,
            manifestNonce: nonce,
            manifestSize: manifestSize
        )
        let headerBytes = header.serialize()

        // Re-encrypt with real header AAD
        let (ciphertext, tag) = try manifest.encrypt(masterKey: masterKey, nonce: nonce, headerAAD: headerBytes)
        XCTAssertEqual(UInt32(ciphertext.count + tag.count), manifestSize)

        let decrypted = try Manifest.decrypt(
            ciphertext: ciphertext,
            tag: tag,
            masterKey: masterKey,
            nonce: nonce,
            headerAAD: headerBytes
        )
        XCTAssertEqual(decrypted, manifest)
    }
}
