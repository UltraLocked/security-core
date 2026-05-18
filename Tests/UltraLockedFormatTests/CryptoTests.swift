import XCTest
import CryptoKit
@testable import UltraLockedFormat

final class CryptoTests: XCTestCase {

    private func fixedMasterKey() -> SymmetricKey {
        SymmetricKey(data: Data(repeating: 0x42, count: 32))
    }

    private func fixedNonce() -> Data {
        Data(repeating: 0x33, count: 12)
    }

    // MARK: HKDF

    func testManifestKeyDerivationIsDeterministic() {
        let master = fixedMasterKey()
        let k1 = Crypto.deriveManifestKey(masterKey: master)
        let k2 = Crypto.deriveManifestKey(masterKey: master)
        let bytes1 = k1.withUnsafeBytes { Data($0) }
        let bytes2 = k2.withUnsafeBytes { Data($0) }
        XCTAssertEqual(bytes1, bytes2)
        XCTAssertEqual(bytes1.count, Crypto.derivedKeySize)
    }

    func testManifestKeyDiffersFromItemKey() {
        let master = fixedMasterKey()
        let manifestKey = Crypto.deriveManifestKey(masterKey: master)
        let itemKey = Crypto.deriveItemKey(masterKey: master, itemID: UUID())
        let manifestBytes = manifestKey.withUnsafeBytes { Data($0) }
        let itemBytes = itemKey.withUnsafeBytes { Data($0) }
        XCTAssertNotEqual(manifestBytes, itemBytes)
    }

    func testItemKeyDiffersByItemID() {
        let master = fixedMasterKey()
        let id1 = UUID(uuidString: "550E8400-E29B-41D4-A716-446655440000")!
        let id2 = UUID(uuidString: "550E8400-E29B-41D4-A716-446655440001")!
        let k1 = Crypto.deriveItemKey(masterKey: master, itemID: id1)
        let k2 = Crypto.deriveItemKey(masterKey: master, itemID: id2)
        let bytes1 = k1.withUnsafeBytes { Data($0) }
        let bytes2 = k2.withUnsafeBytes { Data($0) }
        XCTAssertNotEqual(bytes1, bytes2)
    }

    func testItemKeyDeterministicForSameItemID() {
        let master = fixedMasterKey()
        let id = UUID(uuidString: "550E8400-E29B-41D4-A716-446655440000")!
        let k1 = Crypto.deriveItemKey(masterKey: master, itemID: id)
        let k2 = Crypto.deriveItemKey(masterKey: master, itemID: id)
        let bytes1 = k1.withUnsafeBytes { Data($0) }
        let bytes2 = k2.withUnsafeBytes { Data($0) }
        XCTAssertEqual(bytes1, bytes2)
    }

    func testDifferentMasterKeyProducesDifferentDerivedKey() {
        let master1 = SymmetricKey(data: Data(repeating: 0x01, count: 32))
        let master2 = SymmetricKey(data: Data(repeating: 0x02, count: 32))
        let k1 = Crypto.deriveManifestKey(masterKey: master1)
        let k2 = Crypto.deriveManifestKey(masterKey: master2)
        let bytes1 = k1.withUnsafeBytes { Data($0) }
        let bytes2 = k2.withUnsafeBytes { Data($0) }
        XCTAssertNotEqual(bytes1, bytes2)
    }

    // MARK: AES-GCM

    func testAESGCMRoundtrip() throws {
        let key = fixedMasterKey()
        let nonce = fixedNonce()
        let plaintext = Data("hello world".utf8)
        let aad = Data("header bytes".utf8)
        let (ciphertext, tag) = try Crypto.sealGCM(key: key, nonce: nonce, plaintext: plaintext, aad: aad)
        XCTAssertEqual(tag.count, 16)
        XCTAssertEqual(ciphertext.count, plaintext.count)
        let decrypted = try Crypto.openGCM(key: key, nonce: nonce, ciphertext: ciphertext, tag: tag, aad: aad)
        XCTAssertEqual(decrypted, plaintext)
    }

    func testAESGCMRejectsTamperedCiphertext() throws {
        let key = fixedMasterKey()
        let nonce = fixedNonce()
        let plaintext = Data("hello world".utf8)
        let aad = Data("aad".utf8)
        let result = try Crypto.sealGCM(key: key, nonce: nonce, plaintext: plaintext, aad: aad)
        // CryptoKit may return Data with non-zero startIndex; rebase to a fresh Data
        // before mutating, otherwise [0] subscripts the wrong byte (or traps).
        var ciphertext = Data(result.ciphertext)
        ciphertext[0] ^= 0x01
        XCTAssertThrowsError(try Crypto.openGCM(key: key, nonce: nonce, ciphertext: ciphertext, tag: result.tag, aad: aad)) { error in
            XCTAssertEqual(error as? BundleError, .decryptionFailed)
        }
    }

    func testAESGCMRejectsTamperedTag() throws {
        let key = fixedMasterKey()
        let nonce = fixedNonce()
        let plaintext = Data("hello world".utf8)
        let aad = Data("aad".utf8)
        let result = try Crypto.sealGCM(key: key, nonce: nonce, plaintext: plaintext, aad: aad)
        var tag = Data(result.tag)
        tag[0] ^= 0x01
        XCTAssertThrowsError(try Crypto.openGCM(key: key, nonce: nonce, ciphertext: result.ciphertext, tag: tag, aad: aad))
    }

    func testAESGCMRejectsTamperedAAD() throws {
        let key = fixedMasterKey()
        let nonce = fixedNonce()
        let plaintext = Data("hello world".utf8)
        let originalAAD = Data("aad".utf8)
        let tamperedAAD = Data("AAD".utf8)
        let (ciphertext, tag) = try Crypto.sealGCM(key: key, nonce: nonce, plaintext: plaintext, aad: originalAAD)
        XCTAssertThrowsError(try Crypto.openGCM(key: key, nonce: nonce, ciphertext: ciphertext, tag: tag, aad: tamperedAAD))
    }

    func testAESGCMRejectsWrongKey() throws {
        let key = fixedMasterKey()
        let wrongKey = SymmetricKey(data: Data(repeating: 0x99, count: 32))
        let nonce = fixedNonce()
        let plaintext = Data("hello world".utf8)
        let aad = Data("aad".utf8)
        let (ciphertext, tag) = try Crypto.sealGCM(key: key, nonce: nonce, plaintext: plaintext, aad: aad)
        XCTAssertThrowsError(try Crypto.openGCM(key: wrongKey, nonce: nonce, ciphertext: ciphertext, tag: tag, aad: aad))
    }

    func testAESGCMRejectsWrongNonceSize() {
        let key = fixedMasterKey()
        let badNonce = Data(repeating: 0x33, count: 8)
        let plaintext = Data()
        let aad = Data()
        XCTAssertThrowsError(try Crypto.sealGCM(key: key, nonce: badNonce, plaintext: plaintext, aad: aad))
    }

    // MARK: UUID raw bytes

    func testUUIDRawBytesLayout() {
        let uuid = UUID(uuidString: "00112233-4455-6677-8899-AABBCCDDEEFF")!
        let bytes = uuid.rawBytes
        XCTAssertEqual(bytes.count, 16)
        XCTAssertEqual(Array(bytes), [
            0x00, 0x11, 0x22, 0x33,
            0x44, 0x55,
            0x66, 0x77,
            0x88, 0x99,
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
        ])
    }
}
