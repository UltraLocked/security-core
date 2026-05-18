import Foundation
import CryptoKit

/// Constructs a `.ultralocked` bundle from a passphrase and a list of items.
///
/// Usage:
/// ```swift
/// let builder = BundleBuilder(exportLabel: "iPhone backup")
/// builder.add(ItemContent(name: "doc.rtf", mimeType: "application/rtf", plaintext: data))
/// let bundle = try builder.build(passphrase: "correct horse battery staple")
/// // write `bundle` to disk
/// ```
public final class BundleBuilder {

    private var items: [ItemContent] = []
    private let parameters: Argon2idParameters
    private let exportLabel: String?
    private let exportedAt: Date

    public init(
        parameters: Argon2idParameters = .recommendedDefault,
        exportLabel: String? = nil,
        exportedAt: Date = Date()
    ) {
        self.parameters = parameters
        self.exportLabel = exportLabel
        self.exportedAt = exportedAt
    }

    public func add(_ item: ItemContent) {
        items.append(item)
    }

    /// Build the bundle, deriving the master key from the passphrase via Argon2id.
    public func build(passphrase: String) throws -> Data {
        let salt = Random.bytes(BundleHeader.saltSize)
        let manifestNonce = Random.bytes(BundleHeader.manifestNonceSize)
        let masterKey = try Argon2id.deriveKey(
            passphrase: passphrase,
            salt: salt,
            parameters: parameters
        )
        return try buildBundle(masterKey: masterKey, salt: salt, manifestNonce: manifestNonce)
    }

    /// Test-only path: build the bundle with a pre-derived master key, skipping Argon2.
    /// Used by package tests so end-to-end roundtrips don't depend on libargon2 being
    /// integrated. Production code must use `build(passphrase:)`.
    internal func build(
        masterKey: SymmetricKey,
        salt: Data,
        manifestNonce: Data
    ) throws -> Data {
        try buildBundle(masterKey: masterKey, salt: salt, manifestNonce: manifestNonce)
    }

    // MARK: - Implementation

    private func buildBundle(
        masterKey: SymmetricKey,
        salt: Data,
        manifestNonce: Data
    ) throws -> Data {
        // 1. Stage per-item nonces and predicted item sizes (plaintext + 16 byte tag).
        var itemNonces: [Data] = []
        var descriptors: [ItemDescriptor] = []
        for item in items {
            let nonce = Random.bytes(12)
            let itemSize = UInt64(item.plaintext.count + ItemRecord.tagSize)
            try BundleLimits.validateItemSize(itemSize)
            let descriptor = try ItemDescriptor(
                id: item.id,
                name: item.name,
                mimeType: item.mimeType,
                sizeBytes: UInt64(item.plaintext.count),
                createdAt: item.createdAt,
                modifiedAt: item.modifiedAt,
                ttlSeconds: item.ttlSeconds,
                ttlOriginEpoch: item.ttlOriginEpoch,
                itemNonce: nonce,
                itemSize: itemSize
            )
            descriptors.append(descriptor)
            itemNonces.append(nonce)
        }

        // 2. Build the manifest plaintext to learn its on-disk size.
        let manifest = Manifest(
            exportedAt: exportedAt,
            exportLabel: exportLabel,
            items: descriptors
        )
        let manifestPlaintext = try manifest.encodeJSON()
        let manifestCiphertextSize = manifestPlaintext.count + ItemRecord.tagSize
        try BundleLimits.validateManifestSize(UInt32(manifestCiphertextSize))

        // 3. Construct the public header now that manifest_size is known.
        let header = try BundleHeader(
            argon2TimeCost: parameters.timeCost,
            argon2MemoryKiB: parameters.memoryKiB,
            argon2Parallelism: parameters.parallelism,
            salt: salt,
            manifestNonce: manifestNonce,
            manifestSize: UInt32(manifestCiphertextSize)
        )
        let headerBytes = header.serialize()

        // 4. Encrypt the manifest with the full header as AAD.
        let manifestEncrypted = try manifest.encrypt(
            masterKey: masterKey,
            nonce: manifestNonce,
            headerAAD: headerBytes
        )
        precondition(
            manifestEncrypted.ciphertext.count + manifestEncrypted.tag.count == manifestCiphertextSize,
            "manifest ciphertext+tag size mismatch"
        )

        // 5. Encrypt each item with (header || item_id) as AAD.
        var itemRecords: [Data] = []
        var totalItemBytes = 0
        for (i, item) in items.enumerated() {
            let record = try ItemRecord.encrypt(
                plaintext: item.plaintext,
                masterKey: masterKey,
                itemID: item.id,
                nonce: itemNonces[i],
                headerAAD: headerBytes
            )
            precondition(
                UInt64(record.count) == descriptors[i].itemSize,
                "item record size mismatch for \(item.id)"
            )
            itemRecords.append(record)
            totalItemBytes += record.count
        }

        // 6. Concatenate: [header][manifest_ciphertext][manifest_tag][item_records...]
        let totalSize = BundleHeader.totalSize + manifestCiphertextSize + totalItemBytes
        try BundleLimits.validateTotalFileSize(UInt64(totalSize))

        var output = Data(capacity: totalSize)
        output.append(headerBytes)
        output.append(manifestEncrypted.ciphertext)
        output.append(manifestEncrypted.tag)
        for record in itemRecords {
            output.append(record)
        }
        precondition(output.count == totalSize, "final bundle size mismatch")
        return output
    }
}
