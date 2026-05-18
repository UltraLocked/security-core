import Foundation
import CryptoKit

/// Per-item encryption helpers.
///
/// Each item in the bundle is encrypted with a unique key derived from the master
/// key and the item's UUID, with AAD = public_header_bytes || item_id_bytes. The
/// id-based AAD prevents an attacker from swapping one item's ciphertext with
/// another's even when both are encrypted under the same master key.
///
/// On-disk layout (within the [Encrypted Items] section):
/// ```
/// item_record_i = ciphertext_i || tag_i        (tag is 16 bytes at the end)
/// ```
///
/// `ItemDescriptor.itemSize` records the total record length so the parser can
/// locate each item without scanning.
internal enum ItemRecord {

    /// AES-GCM auth tag length in bytes.
    static let tagSize: Int = 16

    /// Encrypt a single item's plaintext. Returns `ciphertext || tag` concatenated
    /// in the order they should appear on disk.
    static func encrypt(
        plaintext: Data,
        masterKey: SymmetricKey,
        itemID: UUID,
        nonce: Data,
        headerAAD: Data
    ) throws -> Data {
        let itemKey = Crypto.deriveItemKey(masterKey: masterKey, itemID: itemID)
        var aad = Data(headerAAD)
        aad.append(itemID.rawBytes)
        let (ciphertext, tag) = try Crypto.sealGCM(
            key: itemKey,
            nonce: nonce,
            plaintext: plaintext,
            aad: aad
        )
        var record = Data(capacity: ciphertext.count + tag.count)
        record.append(ciphertext)
        record.append(tag)
        return record
    }

    /// Decrypt a single item record (`ciphertext || tag` concatenated). Tampering
    /// with any byte of the record, the header AAD, or supplying the wrong item id
    /// or master key produces `BundleError.decryptionFailed`.
    static func decrypt(
        record: Data,
        masterKey: SymmetricKey,
        itemID: UUID,
        nonce: Data,
        headerAAD: Data
    ) throws -> Data {
        let normalized = Data(record)
        guard normalized.count >= tagSize else {
            throw BundleError.truncated(expected: tagSize, actual: normalized.count)
        }
        let tagOffset = normalized.count - tagSize
        let ciphertext = normalized.subdata(in: 0..<tagOffset)
        let tag = normalized.subdata(in: tagOffset..<normalized.count)
        let itemKey = Crypto.deriveItemKey(masterKey: masterKey, itemID: itemID)
        var aad = Data(headerAAD)
        aad.append(itemID.rawBytes)
        return try Crypto.openGCM(
            key: itemKey,
            nonce: nonce,
            ciphertext: ciphertext,
            tag: tag,
            aad: aad
        )
    }
}
