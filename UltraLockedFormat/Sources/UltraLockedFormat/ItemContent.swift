import Foundation

/// User-facing description of one item to include in a bundle export.
///
/// Pass instances of this to `BundleBuilder.add(_:)`. The builder takes care of
/// generating the per-item nonce, encrypting the plaintext, and wiring up the
/// descriptor that lands in the manifest.
public struct ItemContent {
    public let id: UUID
    public let name: String
    public let mimeType: String
    public let plaintext: Data
    public let createdAt: Date
    public let modifiedAt: Date

    /// TTL preserved from the source `VaultItem`. Both fields must be present or both absent.
    public let ttlSeconds: UInt64?
    public let ttlOriginEpoch: Date?

    public init(
        id: UUID = UUID(),
        name: String,
        mimeType: String,
        plaintext: Data,
        createdAt: Date = Date(),
        modifiedAt: Date = Date(),
        ttlSeconds: UInt64? = nil,
        ttlOriginEpoch: Date? = nil
    ) {
        self.id = id
        self.name = name
        self.mimeType = mimeType
        self.plaintext = plaintext
        self.createdAt = createdAt
        self.modifiedAt = modifiedAt
        self.ttlSeconds = ttlSeconds
        self.ttlOriginEpoch = ttlOriginEpoch
    }
}
