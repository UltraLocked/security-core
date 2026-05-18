import XCTest
import CryptoKit
@testable import UltraLockedFormat

final class Argon2idTests: XCTestCase {

    /// Use minimal parameters (1 iteration, 8 KiB memory, 1 lane) for tests so they
    /// stay fast. The crypto wrapper is what's under test; libargon2 itself is
    /// upstream-validated.
    private func minimalParams() throws -> Argon2idParameters {
        try Argon2idParameters(timeCost: 1, memoryKiB: 8, parallelism: 1)
    }

    private func fixedSalt() -> Data { Data(repeating: 0xAB, count: 16) }

    // MARK: Parameters

    func testRecommendedDefaultIsValid() {
        let p = Argon2idParameters.recommendedDefault
        XCTAssertEqual(p.timeCost, 3)
        XCTAssertEqual(p.memoryKiB, 64 * 1024)
        XCTAssertEqual(p.parallelism, 4)
    }

    func testParametersConstructorValidates() {
        XCTAssertThrowsError(try Argon2idParameters(timeCost: 11, memoryKiB: 65536, parallelism: 4))
        XCTAssertThrowsError(try Argon2idParameters(timeCost: 3, memoryKiB: 7, parallelism: 4))
        XCTAssertThrowsError(try Argon2idParameters(timeCost: 3, memoryKiB: 65536, parallelism: 0))
        XCTAssertNoThrow(try Argon2idParameters(timeCost: 3, memoryKiB: 65536, parallelism: 4))
    }

    // MARK: Input validation

    func testDeriveKeyRejectsEmptyPassphrase() throws {
        let params = try minimalParams()
        XCTAssertThrowsError(try Argon2id.deriveKey(
            passphrase: "",
            salt: fixedSalt(),
            parameters: params
        )) { error in
            guard case .parameterOutOfBounds = error as? BundleError else {
                XCTFail("expected parameterOutOfBounds, got \(error)")
                return
            }
        }
    }

    func testDeriveKeyRejectsWrongSaltSize() throws {
        let params = try minimalParams()
        XCTAssertThrowsError(try Argon2id.deriveKey(
            passphrase: "test",
            salt: Data(repeating: 0xAB, count: 8),
            parameters: params
        )) { error in
            guard case .parameterOutOfBounds = error as? BundleError else {
                XCTFail("expected parameterOutOfBounds, got \(error)")
                return
            }
        }
    }

    // MARK: Output basics

    func testDeriveKeyOutputSize() throws {
        let key = try Argon2id.deriveKey(
            passphrase: "test",
            salt: fixedSalt(),
            parameters: minimalParams()
        )
        let bytes = key.withUnsafeBytes { Data($0) }
        XCTAssertEqual(bytes.count, Argon2id.keyLengthBytes)
        XCTAssertEqual(bytes.count, 32)
    }

    /// Same input → same output. Validates determinism (and basic libargon2 wiring).
    func testDeriveKeyIsDeterministic() throws {
        let params = try minimalParams()
        let salt = fixedSalt()
        let k1 = try Argon2id.deriveKey(passphrase: "test", salt: salt, parameters: params)
        let k2 = try Argon2id.deriveKey(passphrase: "test", salt: salt, parameters: params)
        XCTAssertEqual(k1.withUnsafeBytes { Data($0) }, k2.withUnsafeBytes { Data($0) })
    }

    // MARK: Sensitivity to inputs

    func testDifferentPassphrasesProduceDifferentKeys() throws {
        let params = try minimalParams()
        let salt = fixedSalt()
        let k1 = try Argon2id.deriveKey(passphrase: "alpha", salt: salt, parameters: params)
        let k2 = try Argon2id.deriveKey(passphrase: "beta", salt: salt, parameters: params)
        XCTAssertNotEqual(k1.withUnsafeBytes { Data($0) }, k2.withUnsafeBytes { Data($0) })
    }

    func testDifferentSaltsProduceDifferentKeys() throws {
        let params = try minimalParams()
        let s1 = Data(repeating: 0x01, count: 16)
        let s2 = Data(repeating: 0x02, count: 16)
        let k1 = try Argon2id.deriveKey(passphrase: "test", salt: s1, parameters: params)
        let k2 = try Argon2id.deriveKey(passphrase: "test", salt: s2, parameters: params)
        XCTAssertNotEqual(k1.withUnsafeBytes { Data($0) }, k2.withUnsafeBytes { Data($0) })
    }

    func testDifferentTimeCostProducesDifferentKey() throws {
        let salt = fixedSalt()
        let p1 = try Argon2idParameters(timeCost: 1, memoryKiB: 8, parallelism: 1)
        let p2 = try Argon2idParameters(timeCost: 2, memoryKiB: 8, parallelism: 1)
        let k1 = try Argon2id.deriveKey(passphrase: "test", salt: salt, parameters: p1)
        let k2 = try Argon2id.deriveKey(passphrase: "test", salt: salt, parameters: p2)
        XCTAssertNotEqual(k1.withUnsafeBytes { Data($0) }, k2.withUnsafeBytes { Data($0) })
    }

    func testDifferentMemoryProducesDifferentKey() throws {
        let salt = fixedSalt()
        let p1 = try Argon2idParameters(timeCost: 1, memoryKiB: 8, parallelism: 1)
        let p2 = try Argon2idParameters(timeCost: 1, memoryKiB: 16, parallelism: 1)
        let k1 = try Argon2id.deriveKey(passphrase: "test", salt: salt, parameters: p1)
        let k2 = try Argon2id.deriveKey(passphrase: "test", salt: salt, parameters: p2)
        XCTAssertNotEqual(k1.withUnsafeBytes { Data($0) }, k2.withUnsafeBytes { Data($0) })
    }

    // MARK: End-to-end Builder + Parser with real Argon2

    /// The whole story: encrypt with a passphrase, decrypt with the same passphrase.
    /// Uses minimal parameters so the test runs in milliseconds.
    func testFullPassphraseRoundtrip() throws {
        let params = try minimalParams()
        let plaintext = Data("the quick brown fox".utf8)

        let builder = BundleBuilder(
            parameters: params,
            exportLabel: "passphrase-test",
            exportedAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
        builder.add(ItemContent(
            name: "fox.txt",
            mimeType: "text/plain",
            plaintext: plaintext,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_000)
        ))

        let bytes = try builder.build(passphrase: "correct horse battery staple")

        let parser = try BundleParser(data: bytes)
        let manifest = try parser.unlock(passphrase: "correct horse battery staple")
        XCTAssertEqual(manifest.items.count, 1)
        XCTAssertEqual(manifest.items[0].name, "fox.txt")
        let decrypted = try parser.decrypt(item: manifest.items[0])
        XCTAssertEqual(decrypted, plaintext)
    }

    func testWrongPassphraseRejected() throws {
        let params = try minimalParams()
        let builder = BundleBuilder(parameters: params)
        builder.add(ItemContent(name: "x", mimeType: "application/octet-stream", plaintext: Data("secret".utf8)))
        let bytes = try builder.build(passphrase: "right passphrase")
        let parser = try BundleParser(data: bytes)
        XCTAssertThrowsError(try parser.unlock(passphrase: "wrong passphrase")) { error in
            XCTAssertEqual(error as? BundleError, .decryptionFailed)
        }
    }
}
