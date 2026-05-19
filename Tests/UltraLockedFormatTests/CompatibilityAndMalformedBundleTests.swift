import CryptoKit
import XCTest
@testable import UltraLockedFormat

final class CompatibilityAndMalformedBundleTests: XCTestCase {
    private let masterKey = SymmetricKey(data: Data(repeating: 0x42, count: 32))
    private let salt = Data(repeating: 0xAB, count: 16)
    private let manifestNonce = Data(repeating: 0xCD, count: 12)

    func testGoldenHeaderCompatibility() throws {
        let content = ItemContent(
            id: UUID(uuidString: "11111111-1111-1111-1111-111111111111")!,
            name: "seed.txt",
            mimeType: "text/plain",
            plaintext: Data("stable paid-user backup".utf8),
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_000),
            ttlSeconds: 3600,
            ttlOriginEpoch: Date(timeIntervalSince1970: 1_700_000_000)
        )

        let first = try makeBundle(with: content)

        let expectedHeader = try BundleHeader(
            argon2TimeCost: Argon2idParameters.recommendedDefault.timeCost,
            argon2MemoryKiB: Argon2idParameters.recommendedDefault.memoryKiB,
            argon2Parallelism: Argon2idParameters.recommendedDefault.parallelism,
            salt: salt,
            manifestNonce: manifestNonce,
            manifestSize: 400
        ).serialize()
        XCTAssertEqual(first.prefix(BundleHeader.totalSize), expectedHeader)

        let parser = try BundleParser(data: first)
        let manifest = try parser.unlock(masterKey: masterKey)
        XCTAssertEqual(manifest.items.map(\.id), [content.id])
        XCTAssertEqual(manifest.items[0].ttlSeconds, 3600)
        XCTAssertEqual(try parser.decrypt(item: manifest.items[0]), content.plaintext)
    }

    func testMalformedBundleCorpusFailsClosed() throws {
        let valid = try makeBundle(with: ItemContent(
            id: UUID(uuidString: "22222222-2222-2222-2222-222222222222")!,
            name: "valid.bin",
            mimeType: "application/octet-stream",
            plaintext: Data([0x00, 0x01, 0x02]),
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            modifiedAt: Date(timeIntervalSince1970: 1_700_000_000),
            ttlSeconds: nil,
            ttlOriginEpoch: nil
        ))

        var truncatedManifest = valid
        truncatedManifest.removeLast()

        var corruptMagic = valid
        corruptMagic[0] ^= 0xFF

        var corruptVersion = valid
        corruptVersion[8] = 0xFF

        var undersizedManifest = valid
        undersizedManifest[48] = UInt8(BundleLimits.manifestSizeMin - 1)
        undersizedManifest[49] = 0
        undersizedManifest[50] = 0
        undersizedManifest[51] = 0

        let corpus: [Data] = [
            Data(),
            Data(repeating: 0, count: BundleHeader.totalSize - 1),
            corruptMagic,
            corruptVersion,
            undersizedManifest,
            truncatedManifest
        ]

        for malformed in corpus {
            XCTAssertThrowsError(try parseAndUnlock(malformed))
        }
    }

    private func makeBundle(with content: ItemContent) throws -> Data {
        let builder = BundleBuilder(
            parameters: .recommendedDefault,
            exportLabel: "compatibility",
            exportedAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
        builder.add(content)
        return try builder.build(masterKey: masterKey, salt: salt, manifestNonce: manifestNonce)
    }

    private func parseAndUnlock(_ data: Data) throws {
        let parser = try BundleParser(data: data)
        _ = try parser.unlock(masterKey: masterKey)
    }
}
