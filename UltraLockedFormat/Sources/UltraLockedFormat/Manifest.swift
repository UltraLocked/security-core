import Foundation
import CryptoKit

/// Per-item descriptor stored inside the encrypted manifest.
///
/// Each descriptor names exactly one entry in the [Encrypted Items] section. The
/// `itemNonce` and `itemSize` together let the parser locate and decrypt the item
/// without scanning the file.
public struct ItemDescriptor: Codable, Equatable {

    public let id: UUID
    public let name: String
    public let mimeType: String

    /// Plaintext size in bytes (informational, used by UI for "this export contains 4MiB of items").
    public let sizeBytes: UInt64

    public let createdAt: Date
    public let modifiedAt: Date

    /// TTL preserved from the source `VaultItem`. `nil` if the item had no expiration.
    public let ttlSeconds: UInt64?
    /// Origin timestamp the TTL was measured from, so the receiver can compute remaining time.
    public let ttlOriginEpoch: Date?

    /// 12-byte AES-GCM nonce for the item record.
    public let itemNonce: Data
    /// Ciphertext+tag length on disk (in bytes). Bounded by `BundleLimits.itemSizeMax`.
    public let itemSize: UInt64

    public init(
        id: UUID,
        name: String,
        mimeType: String,
        sizeBytes: UInt64,
        createdAt: Date,
        modifiedAt: Date,
        ttlSeconds: UInt64?,
        ttlOriginEpoch: Date?,
        itemNonce: Data,
        itemSize: UInt64
    ) throws {
        guard itemNonce.count == 12 else {
            throw BundleError.parameterOutOfBounds("item_nonce must be 12 bytes, got \(itemNonce.count)")
        }
        try BundleLimits.validateItemSize(itemSize)
        try ItemDescriptor.validateTTLConsistency(ttlSeconds: ttlSeconds, ttlOriginEpoch: ttlOriginEpoch, itemID: id)

        self.id = id
        self.name = name
        self.mimeType = mimeType
        self.sizeBytes = sizeBytes
        self.createdAt = createdAt
        self.modifiedAt = modifiedAt
        self.ttlSeconds = ttlSeconds
        self.ttlOriginEpoch = ttlOriginEpoch
        self.itemNonce = itemNonce
        self.itemSize = itemSize
    }

    /// Validate fields after JSON decode (Decodable's synthesized init bypasses our validating init).
    func validate() throws {
        guard itemNonce.count == 12 else {
            throw BundleError.manifestParseFailed("item_nonce for \(id) must be 12 bytes, got \(itemNonce.count)")
        }
        try BundleLimits.validateItemSize(itemSize)
        try ItemDescriptor.validateTTLConsistency(ttlSeconds: ttlSeconds, ttlOriginEpoch: ttlOriginEpoch, itemID: id)
    }

    private static func validateTTLConsistency(ttlSeconds: UInt64?, ttlOriginEpoch: Date?, itemID: UUID) throws {
        // TTL fields must be both present or both absent.
        switch (ttlSeconds, ttlOriginEpoch) {
        case (nil, nil), (.some, .some): return
        default:
            throw BundleError.manifestParseFailed(
                "TTL fields for \(itemID) must be both present or both absent"
            )
        }
    }
}

/// Manifest plaintext: the JSON document that sits inside the [Encrypted Manifest] block.
///
/// Serialized as JSON with snake_case keys, ISO-8601 dates, base64 Data, and sorted keys
/// for determinism. The serialized bytes are then encrypted with `manifest_key` (HKDF of
/// the master key) under AES-256-GCM with the public header as AAD.
public struct Manifest: Codable, Equatable {

    public static let currentSchemaVersion: Int = 1

    public let schemaVersion: Int
    public let exportedAt: Date
    public let exportLabel: String?
    public let items: [ItemDescriptor]

    public init(
        exportedAt: Date = Date(),
        exportLabel: String? = nil,
        items: [ItemDescriptor]
    ) {
        self.schemaVersion = Manifest.currentSchemaVersion
        self.exportedAt = exportedAt
        self.exportLabel = exportLabel
        self.items = items
    }

    // MARK: JSON encode/decode

    /// Encode to deterministic JSON bytes (sorted keys, ISO-8601 dates, base64 Data, snake_case keys).
    public func encodeJSON() throws -> Data {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        encoder.dateEncodingStrategy = .iso8601
        encoder.dataEncodingStrategy = .base64
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(self)
    }

    /// Decode from JSON bytes and validate.
    public static func decodeJSON(_ data: Data) throws -> Manifest {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        decoder.dateDecodingStrategy = .iso8601
        decoder.dataDecodingStrategy = .base64
        let manifest: Manifest
        do {
            manifest = try decoder.decode(Manifest.self, from: data)
        } catch {
            throw BundleError.manifestParseFailed("\(error)")
        }
        try manifest.validate()
        return manifest
    }

    /// Validate the decoded manifest. Applies hard limits and structural checks
    /// that Decodable's synthesized init can't enforce on its own.
    func validate() throws {
        guard schemaVersion == Manifest.currentSchemaVersion else {
            throw BundleError.manifestParseFailed("unsupported schema_version \(schemaVersion)")
        }
        for item in items {
            try item.validate()
        }
        // Item-id uniqueness within a manifest.
        var seen = Set<UUID>()
        for item in items {
            if !seen.insert(item.id).inserted {
                throw BundleError.manifestParseFailed("duplicate item id \(item.id) in manifest")
            }
        }
    }

    // MARK: Encrypt / decrypt

    /// Encrypt this manifest under the master key with the public header as AAD.
    /// Returns the AES-GCM `(ciphertext, tag)` pair to be written after the header on disk.
    public func encrypt(
        masterKey: SymmetricKey,
        nonce: Data,
        headerAAD: Data
    ) throws -> (ciphertext: Data, tag: Data) {
        let plaintext = try encodeJSON()
        let manifestKey = Crypto.deriveManifestKey(masterKey: masterKey)
        return try Crypto.sealGCM(
            key: manifestKey,
            nonce: nonce,
            plaintext: plaintext,
            aad: headerAAD
        )
    }

    /// Decrypt a manifest from on-disk bytes. Tampering with `headerAAD`, `ciphertext`,
    /// or `tag` causes `BundleError.decryptionFailed`.
    public static func decrypt(
        ciphertext: Data,
        tag: Data,
        masterKey: SymmetricKey,
        nonce: Data,
        headerAAD: Data
    ) throws -> Manifest {
        let manifestKey = Crypto.deriveManifestKey(masterKey: masterKey)
        let plaintext = try Crypto.openGCM(
            key: manifestKey,
            nonce: nonce,
            ciphertext: ciphertext,
            tag: tag,
            aad: headerAAD
        )
        return try Manifest.decodeJSON(plaintext)
    }
}
