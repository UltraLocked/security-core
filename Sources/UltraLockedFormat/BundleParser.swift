import Foundation
import CryptoKit

/// Parses a `.ultralocked` bundle. Two-phase API:
///
/// 1. `init(data:)` validates the public header and bounds-checks against `BundleLimits`.
///    No decryption happens here, so the parser can hand back filesystem-level
///    information for a UI preview before the user types a passphrase.
/// 2. `unlock(passphrase:)` derives the master key and decrypts the manifest. After
///    unlock, individual items can be decrypted via `decrypt(item:)`.
///
/// `lock()` zeroes the in-memory references to the master key and manifest.
public final class BundleParser {

    /// The validated public header. Available immediately, before unlock.
    public let header: BundleHeader

    /// Total file size in bytes.
    public var totalSize: Int { data.count }

    private let data: Data
    private let headerBytes: Data
    private var masterKey: SymmetricKey?
    private var cachedManifest: Manifest?

    public init(data: Data) throws {
        try BundleLimits.validateTotalFileSize(UInt64(data.count))
        // Normalize startIndex so byte arithmetic is straightforward.
        let normalized = Data(data)

        let parsedHeader = try BundleHeader.parse(normalized)

        // Verify the manifest section fits.
        let manifestStart = BundleHeader.totalSize
        let manifestEnd = manifestStart + Int(parsedHeader.manifestSize)
        guard normalized.count >= manifestEnd else {
            throw BundleError.truncated(expected: manifestEnd, actual: normalized.count)
        }

        self.header = parsedHeader
        self.data = normalized
        self.headerBytes = normalized.subdata(in: 0..<BundleHeader.totalSize)
    }

    /// Unlock the bundle by deriving the master key from the passphrase via Argon2id,
    /// decrypting and validating the manifest. Returns the manifest for UI preview.
    public func unlock(passphrase: String) throws -> Manifest {
        let parameters = try Argon2idParameters(
            timeCost: header.argon2TimeCost,
            memoryKiB: header.argon2MemoryKiB,
            parallelism: header.argon2Parallelism
        )
        let key = try Argon2id.deriveKey(
            passphrase: passphrase,
            salt: header.salt,
            parameters: parameters
        )
        return try unlockWithKey(key)
    }

    /// Test-only path: unlock with a pre-derived master key, skipping Argon2.
    /// Production code must use `unlock(passphrase:)`.
    internal func unlock(masterKey key: SymmetricKey) throws -> Manifest {
        try unlockWithKey(key)
    }

    /// Decrypt a single item by its descriptor. Requires `unlock(...)` to have been
    /// called first; throws otherwise.
    ///
    /// Items can be decrypted in any order, lazily, so a UI can let the user choose
    /// which to import without paying for the full payload upfront.
    public func decrypt(item: ItemDescriptor) throws -> Data {
        guard let key = masterKey, let manifest = cachedManifest else {
            throw BundleError.parameterOutOfBounds("must call unlock(...) before decrypt(item:)")
        }
        guard let index = manifest.items.firstIndex(where: { $0.id == item.id }) else {
            throw BundleError.manifestParseFailed("item \(item.id) is not in this bundle's manifest")
        }

        // Compute the byte offset of the requested item by accumulating preceding item sizes.
        var offset = BundleHeader.totalSize + Int(header.manifestSize)
        for i in 0..<index {
            offset += Int(manifest.items[i].itemSize)
        }
        let recordEnd = offset + Int(item.itemSize)
        guard data.count >= recordEnd else {
            throw BundleError.truncated(expected: recordEnd, actual: data.count)
        }
        let record = data.subdata(in: offset..<recordEnd)

        return try ItemRecord.decrypt(
            record: record,
            masterKey: key,
            itemID: item.id,
            nonce: item.itemNonce,
            headerAAD: headerBytes
        )
    }

    /// Drop the cached master key and manifest. Subsequent `decrypt(item:)` calls fail
    /// until the bundle is unlocked again.
    public func lock() {
        masterKey = nil
        cachedManifest = nil
    }

    // MARK: - Implementation

    private func unlockWithKey(_ key: SymmetricKey) throws -> Manifest {
        let manifestStart = BundleHeader.totalSize
        let manifestEnd = manifestStart + Int(header.manifestSize)
        let manifestBytes = data.subdata(in: manifestStart..<manifestEnd)

        // [Encrypted Manifest] = ciphertext || tag (16-byte tag at the end).
        let tagOffset = manifestBytes.count - ItemRecord.tagSize
        let ciphertext = manifestBytes.subdata(in: 0..<tagOffset)
        let tag = manifestBytes.subdata(in: tagOffset..<manifestBytes.count)

        let manifest = try Manifest.decrypt(
            ciphertext: ciphertext,
            tag: tag,
            masterKey: key,
            nonce: header.manifestNonce,
            headerAAD: headerBytes
        )

        // Sanity: descriptor item sizes must sum to no more than remaining file bytes.
        let itemsByteBudget = data.count - manifestEnd
        let totalItemBytes = manifest.items.reduce(0) { $0 + Int($1.itemSize) }
        guard totalItemBytes <= itemsByteBudget else {
            throw BundleError.manifestParseFailed(
                "manifest item sizes (\(totalItemBytes)) exceed file space (\(itemsByteBudget))"
            )
        }

        self.masterKey = key
        self.cachedManifest = manifest
        return manifest
    }
}
