import Foundation
import CryptoKit

/// Internal crypto helpers used by manifest and item encryption.
///
/// These wrap CryptoKit primitives in the specific HKDF info strings and AES-GCM
/// patterns this format requires. Kept internal so the public API surface is
/// `BundleBuilder` / `BundleParser` only.
internal enum Crypto {

    // MARK: HKDF info constants

    /// HKDF info string used to derive the manifest encryption key from the master key.
    static let manifestKeyInfo = Data("UltraLocked-Export-v1-Manifest".utf8)

    /// HKDF info-prefix used to derive a per-item encryption key from the master key.
    /// The full info bytes are `itemKeyInfoPrefix || item_id_bytes`.
    static let itemKeyInfoPrefix = Data("UltraLocked-Export-v1-Item-".utf8)

    /// Size of derived keys in bytes (256-bit for AES-256-GCM).
    static let derivedKeySize: Int = 32

    // MARK: HKDF derivation

    /// Derive the manifest encryption key from the master key.
    static func deriveManifestKey(masterKey: SymmetricKey) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: masterKey,
            info: manifestKeyInfo,
            outputByteCount: derivedKeySize
        )
    }

    /// Derive a per-item encryption key from the master key and the item's UUID.
    /// The UUID's raw 16 bytes are used for the info suffix.
    static func deriveItemKey(masterKey: SymmetricKey, itemID: UUID) -> SymmetricKey {
        var info = Data(itemKeyInfoPrefix)
        info.append(itemID.rawBytes)
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: masterKey,
            info: info,
            outputByteCount: derivedKeySize
        )
    }

    // MARK: AES-256-GCM

    /// AES-256-GCM seal with separate nonce + AAD.
    /// Returns `(ciphertext, tag)` so callers can lay them out on disk in our format-specific order.
    static func sealGCM(
        key: SymmetricKey,
        nonce: Data,
        plaintext: Data,
        aad: Data
    ) throws -> (ciphertext: Data, tag: Data) {
        let nonceObj = try AES.GCM.Nonce(data: nonce)
        let sealed = try AES.GCM.seal(plaintext, using: key, nonce: nonceObj, authenticating: aad)
        return (sealed.ciphertext, sealed.tag)
    }

    /// AES-256-GCM open. Throws `BundleError.decryptionFailed` on auth failure (wrong key,
    /// tampered ciphertext, tampered AAD, or wrong nonce).
    static func openGCM(
        key: SymmetricKey,
        nonce: Data,
        ciphertext: Data,
        tag: Data,
        aad: Data
    ) throws -> Data {
        let nonceObj = try AES.GCM.Nonce(data: nonce)
        let sealedBox = try AES.GCM.SealedBox(nonce: nonceObj, ciphertext: ciphertext, tag: tag)
        do {
            return try AES.GCM.open(sealedBox, using: key, authenticating: aad)
        } catch {
            throw BundleError.decryptionFailed
        }
    }
}

// MARK: - UUID raw bytes

extension UUID {
    /// Raw 16-byte representation of the UUID, suitable for use as HKDF info or AAD.
    var rawBytes: Data {
        let u = self.uuid
        return Data([
            u.0, u.1, u.2, u.3, u.4, u.5, u.6, u.7,
            u.8, u.9, u.10, u.11, u.12, u.13, u.14, u.15
        ])
    }
}
