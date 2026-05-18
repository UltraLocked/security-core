import XCTest
import CryptoKit
@testable import UltraLockedFormat

final class ItemRecordTests: XCTestCase {

    private func fixedMasterKey() -> SymmetricKey {
        SymmetricKey(data: Data(repeating: 0x42, count: 32))
    }

    private func fixedNonce() -> Data {
        Data(repeating: 0x55, count: 12)
    }

    private func fixedHeader() -> Data {
        Data(repeating: 0xCD, count: 96)
    }

    private let testID = UUID(uuidString: "550E8400-E29B-41D4-A716-446655440000")!

    // MARK: Roundtrip

    func testRoundtripSmallPlaintext() throws {
        let plaintext = Data("hello world".utf8)
        let record = try ItemRecord.encrypt(
            plaintext: plaintext,
            masterKey: fixedMasterKey(),
            itemID: testID,
            nonce: fixedNonce(),
            headerAAD: fixedHeader()
        )
        XCTAssertEqual(record.count, plaintext.count + ItemRecord.tagSize)
        let decrypted = try ItemRecord.decrypt(
            record: record,
            masterKey: fixedMasterKey(),
            itemID: testID,
            nonce: fixedNonce(),
            headerAAD: fixedHeader()
        )
        XCTAssertEqual(decrypted, plaintext)
    }

    func testRoundtripEmptyPlaintext() throws {
        let plaintext = Data()
        let record = try ItemRecord.encrypt(
            plaintext: plaintext,
            masterKey: fixedMasterKey(),
            itemID: testID,
            nonce: fixedNonce(),
            headerAAD: fixedHeader()
        )
        XCTAssertEqual(record.count, ItemRecord.tagSize)
        let decrypted = try ItemRecord.decrypt(
            record: record,
            masterKey: fixedMasterKey(),
            itemID: testID,
            nonce: fixedNonce(),
            headerAAD: fixedHeader()
        )
        XCTAssertEqual(decrypted, plaintext)
    }

    func testRoundtrip1MiBPlaintext() throws {
        let plaintext = Data(repeating: 0x77, count: 1024 * 1024)
        let record = try ItemRecord.encrypt(
            plaintext: plaintext,
            masterKey: fixedMasterKey(),
            itemID: testID,
            nonce: fixedNonce(),
            headerAAD: fixedHeader()
        )
        let decrypted = try ItemRecord.decrypt(
            record: record,
            masterKey: fixedMasterKey(),
            itemID: testID,
            nonce: fixedNonce(),
            headerAAD: fixedHeader()
        )
        XCTAssertEqual(decrypted, plaintext)
        XCTAssertEqual(decrypted.count, plaintext.count)
    }

    // MARK: Tamper detection

    func testRejectsTamperedCiphertext() throws {
        let plaintext = Data("hello world".utf8)
        var record = try ItemRecord.encrypt(
            plaintext: plaintext,
            masterKey: fixedMasterKey(),
            itemID: testID,
            nonce: fixedNonce(),
            headerAAD: fixedHeader()
        )
        record[0] ^= 0x01
        XCTAssertThrowsError(try ItemRecord.decrypt(
            record: record,
            masterKey: fixedMasterKey(),
            itemID: testID,
            nonce: fixedNonce(),
            headerAAD: fixedHeader()
        )) { error in
            XCTAssertEqual(error as? BundleError, .decryptionFailed)
        }
    }

    func testRejectsTamperedTag() throws {
        let plaintext = Data("hello world".utf8)
        var record = try ItemRecord.encrypt(
            plaintext: plaintext,
            masterKey: fixedMasterKey(),
            itemID: testID,
            nonce: fixedNonce(),
            headerAAD: fixedHeader()
        )
        record[record.count - 1] ^= 0x01
        XCTAssertThrowsError(try ItemRecord.decrypt(
            record: record,
            masterKey: fixedMasterKey(),
            itemID: testID,
            nonce: fixedNonce(),
            headerAAD: fixedHeader()
        ))
    }

    func testRejectsTamperedHeaderAAD() throws {
        let plaintext = Data("hello world".utf8)
        let record = try ItemRecord.encrypt(
            plaintext: plaintext,
            masterKey: fixedMasterKey(),
            itemID: testID,
            nonce: fixedNonce(),
            headerAAD: fixedHeader()
        )
        var tampered = fixedHeader()
        tampered[0] ^= 0xFF
        XCTAssertThrowsError(try ItemRecord.decrypt(
            record: record,
            masterKey: fixedMasterKey(),
            itemID: testID,
            nonce: fixedNonce(),
            headerAAD: tampered
        ))
    }

    /// Critical: an item id substituted for another item's id must invalidate the
    /// auth tag, so an attacker cannot move ciphertexts between item slots even
    /// when both items are encrypted under the same master key.
    func testRejectsWrongItemIDEvenWithSameMasterKey() throws {
        let plaintext = Data("secret".utf8)
        let record = try ItemRecord.encrypt(
            plaintext: plaintext,
            masterKey: fixedMasterKey(),
            itemID: testID,
            nonce: fixedNonce(),
            headerAAD: fixedHeader()
        )
        let otherID = UUID(uuidString: "550E8400-E29B-41D4-A716-446655440001")!
        XCTAssertThrowsError(try ItemRecord.decrypt(
            record: record,
            masterKey: fixedMasterKey(),
            itemID: otherID,
            nonce: fixedNonce(),
            headerAAD: fixedHeader()
        ))
    }

    func testRejectsWrongMasterKey() throws {
        let plaintext = Data("hello".utf8)
        let record = try ItemRecord.encrypt(
            plaintext: plaintext,
            masterKey: fixedMasterKey(),
            itemID: testID,
            nonce: fixedNonce(),
            headerAAD: fixedHeader()
        )
        let wrongKey = SymmetricKey(data: Data(repeating: 0x99, count: 32))
        XCTAssertThrowsError(try ItemRecord.decrypt(
            record: record,
            masterKey: wrongKey,
            itemID: testID,
            nonce: fixedNonce(),
            headerAAD: fixedHeader()
        ))
    }

    func testRejectsWrongNonce() throws {
        let plaintext = Data("hello".utf8)
        let record = try ItemRecord.encrypt(
            plaintext: plaintext,
            masterKey: fixedMasterKey(),
            itemID: testID,
            nonce: fixedNonce(),
            headerAAD: fixedHeader()
        )
        let otherNonce = Data(repeating: 0x66, count: 12)
        XCTAssertThrowsError(try ItemRecord.decrypt(
            record: record,
            masterKey: fixedMasterKey(),
            itemID: testID,
            nonce: otherNonce,
            headerAAD: fixedHeader()
        ))
    }

    func testRejectsTruncatedRecord() {
        let truncated = Data(repeating: 0xAA, count: 8) // shorter than tag size
        XCTAssertThrowsError(try ItemRecord.decrypt(
            record: truncated,
            masterKey: fixedMasterKey(),
            itemID: testID,
            nonce: fixedNonce(),
            headerAAD: fixedHeader()
        )) { error in
            XCTAssertEqual(error as? BundleError, .truncated(expected: 16, actual: 8))
        }
    }

    // MARK: Independence

    func testDifferentItemsProduceDifferentCiphertexts() throws {
        let plaintext = Data("same plaintext".utf8)
        let id1 = UUID(uuidString: "00000000-0000-0000-0000-000000000001")!
        let id2 = UUID(uuidString: "00000000-0000-0000-0000-000000000002")!
        let record1 = try ItemRecord.encrypt(
            plaintext: plaintext,
            masterKey: fixedMasterKey(),
            itemID: id1,
            nonce: fixedNonce(),
            headerAAD: fixedHeader()
        )
        let record2 = try ItemRecord.encrypt(
            plaintext: plaintext,
            masterKey: fixedMasterKey(),
            itemID: id2,
            nonce: fixedNonce(),
            headerAAD: fixedHeader()
        )
        // Same plaintext, same nonce, same master key, same header — but different
        // item ids. Different keys → different ciphertexts.
        XCTAssertNotEqual(record1, record2)
    }
}
