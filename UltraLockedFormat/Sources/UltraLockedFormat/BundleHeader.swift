import Foundation

/// Public header of an UltraLocked bundle.
///
/// The header is unauthenticated by itself but is fed as Additional Authenticated Data
/// (AAD) into every subsequent AES-GCM operation, so any tampering invalidates the
/// manifest's auth tag (and, transitively, every item's auth tag).
///
/// On-disk layout (96 bytes, little-endian for multi-byte fields):
/// ```
/// offset  size  field
/// 0       8     magic                "ULOCKED1"
/// 8       2     version              u16
/// 10      1     kdf_id               u8     (1 = argon2id)
/// 11      4     argon2_time_cost     u32
/// 15      4     argon2_memory_kib    u32
/// 19      1     argon2_parallelism   u8
/// 20      16    salt                 random
/// 36      12    manifest_nonce       random
/// 48      4     manifest_size        u32   (length of [Encrypted Manifest] including tag)
/// 52      44    reserved (zeroed)
/// ```
public struct BundleHeader: Equatable {

    /// Magic bytes identifying the file format. ASCII "ULOCKED1".
    public static let magic: [UInt8] = [0x55, 0x4C, 0x4F, 0x43, 0x4B, 0x45, 0x44, 0x31]

    /// Total fixed header size in bytes.
    public static let totalSize: Int = 96

    /// KDF id for Argon2id.
    public static let kdfArgon2id: UInt8 = 1

    /// Salt size in bytes.
    public static let saltSize: Int = 16

    /// Manifest nonce size in bytes (AES-GCM 12-byte nonce).
    public static let manifestNonceSize: Int = 12

    public let version: UInt16
    public let kdfID: UInt8
    public let argon2TimeCost: UInt32
    public let argon2MemoryKiB: UInt32
    public let argon2Parallelism: UInt8
    public let salt: Data
    public let manifestNonce: Data
    public let manifestSize: UInt32

    public init(
        version: UInt16 = 1,
        kdfID: UInt8 = BundleHeader.kdfArgon2id,
        argon2TimeCost: UInt32,
        argon2MemoryKiB: UInt32,
        argon2Parallelism: UInt8,
        salt: Data,
        manifestNonce: Data,
        manifestSize: UInt32
    ) throws {
        guard version == 1 else {
            throw BundleError.unsupportedVersion(version)
        }
        guard kdfID == BundleHeader.kdfArgon2id else {
            throw BundleError.unsupportedKDF(kdfID)
        }
        guard salt.count == BundleHeader.saltSize else {
            throw BundleError.invalidHeader("salt must be exactly \(BundleHeader.saltSize) bytes, got \(salt.count)")
        }
        guard manifestNonce.count == BundleHeader.manifestNonceSize else {
            throw BundleError.invalidHeader("manifest_nonce must be exactly \(BundleHeader.manifestNonceSize) bytes, got \(manifestNonce.count)")
        }
        try BundleLimits.validateArgon2Params(
            timeCost: argon2TimeCost,
            memoryKiB: argon2MemoryKiB,
            parallelism: argon2Parallelism
        )
        try BundleLimits.validateManifestSize(manifestSize)

        self.version = version
        self.kdfID = kdfID
        self.argon2TimeCost = argon2TimeCost
        self.argon2MemoryKiB = argon2MemoryKiB
        self.argon2Parallelism = argon2Parallelism
        self.salt = salt
        self.manifestNonce = manifestNonce
        self.manifestSize = manifestSize
    }

    /// Encode the header to its 96-byte on-disk form.
    public func serialize() -> Data {
        var data = Data(capacity: Self.totalSize)
        data.append(contentsOf: Self.magic)                    // 0..8
        data.appendLittleEndian(version)                       // 8..10
        data.append(kdfID)                                     // 10..11
        data.appendLittleEndian(argon2TimeCost)                // 11..15
        data.appendLittleEndian(argon2MemoryKiB)               // 15..19
        data.append(argon2Parallelism)                         // 19..20
        data.append(salt)                                      // 20..36
        data.append(manifestNonce)                             // 36..48
        data.appendLittleEndian(manifestSize)                  // 48..52
        let padding = Self.totalSize - data.count
        if padding > 0 {
            data.append(Data(count: padding))                  // 52..96 (zeros)
        }
        precondition(data.count == Self.totalSize, "header serialization size mismatch")
        return data
    }

    /// Parse a `BundleHeader` from its 96-byte on-disk form.
    /// Validates magic, version, kdf id, sizes, and limits before constructing.
    public static func parse(_ input: Data) throws -> BundleHeader {
        guard input.count >= totalSize else {
            throw BundleError.truncated(expected: totalSize, actual: input.count)
        }
        // Normalize startIndex by copying into a fresh Data so that subscripting works from 0.
        let data = Data(input.prefix(totalSize))

        // Magic
        for i in 0..<magic.count {
            if data[i] != magic[i] {
                throw BundleError.invalidHeader("magic mismatch at byte \(i)")
            }
        }

        let version: UInt16 = data.readLittleEndian(at: 8)
        let kdfID: UInt8 = data[10]
        let argon2TimeCost: UInt32 = data.readLittleEndian(at: 11)
        let argon2MemoryKiB: UInt32 = data.readLittleEndian(at: 15)
        let argon2Parallelism: UInt8 = data[19]
        let salt = data.subdata(in: 20..<36)
        let manifestNonce = data.subdata(in: 36..<48)
        let manifestSize: UInt32 = data.readLittleEndian(at: 48)

        return try BundleHeader(
            version: version,
            kdfID: kdfID,
            argon2TimeCost: argon2TimeCost,
            argon2MemoryKiB: argon2MemoryKiB,
            argon2Parallelism: argon2Parallelism,
            salt: salt,
            manifestNonce: manifestNonce,
            manifestSize: manifestSize
        )
    }
}

// MARK: - Internal byte helpers

extension Data {

    fileprivate mutating func appendLittleEndian(_ value: UInt16) {
        var le = value.littleEndian
        Swift.withUnsafeBytes(of: &le) { append(contentsOf: $0) }
    }

    fileprivate mutating func appendLittleEndian(_ value: UInt32) {
        var le = value.littleEndian
        Swift.withUnsafeBytes(of: &le) { append(contentsOf: $0) }
    }

    fileprivate func readLittleEndian(at offset: Int) -> UInt16 {
        let lo = UInt16(self[offset])
        let hi = UInt16(self[offset + 1])
        return lo | (hi << 8)
    }

    fileprivate func readLittleEndian(at offset: Int) -> UInt32 {
        let b0 = UInt32(self[offset])
        let b1 = UInt32(self[offset + 1])
        let b2 = UInt32(self[offset + 2])
        let b3 = UInt32(self[offset + 3])
        return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    }
}
