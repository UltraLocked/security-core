import Foundation
import CryptoKit
import CArgon2

/// Argon2id parameters used to derive a master key from a user passphrase.
/// Bounded by `BundleLimits` to defend against malicious bundles requesting absurd
/// CPU/RAM at parse time.
public struct Argon2idParameters: Equatable, Hashable {
    public let timeCost: UInt32        // iterations
    public let memoryKiB: UInt32       // memory in KiB
    public let parallelism: UInt8      // lanes

    public init(timeCost: UInt32, memoryKiB: UInt32, parallelism: UInt8) throws {
        try BundleLimits.validateArgon2Params(
            timeCost: timeCost,
            memoryKiB: memoryKiB,
            parallelism: parallelism
        )
        self.timeCost = timeCost
        self.memoryKiB = memoryKiB
        self.parallelism = parallelism
    }

    /// Recommended defaults targeting roughly one second of work on a recent iPhone.
    /// Re-tune annually as hardware improves; bumping these does not break old bundles
    /// since the parameters are stored in each header.
    public static let recommendedDefault: Argon2idParameters = {
        // Force-unwrap is safe: the values are within `BundleLimits`.
        // swiftlint:disable:next force_try
        try! Argon2idParameters(timeCost: 3, memoryKiB: 64 * 1024, parallelism: 4)
    }()
}

/// Argon2id master-key derivation, backed by libargon2 (PHC reference implementation).
///
/// See `Package.swift` for the vendored upstream version and license.
public enum Argon2id {

    /// Output key length in bytes (32 = 256-bit key for AES-256-GCM).
    public static let keyLengthBytes: Int = 32

    /// Derive a 32-byte master key from the passphrase + salt using Argon2id.
    public static func deriveKey(
        passphrase: String,
        salt: Data,
        parameters: Argon2idParameters
    ) throws -> SymmetricKey {
        guard !passphrase.isEmpty else {
            throw BundleError.parameterOutOfBounds("passphrase must not be empty")
        }
        guard salt.count == BundleHeader.saltSize else {
            throw BundleError.parameterOutOfBounds(
                "salt must be \(BundleHeader.saltSize) bytes, got \(salt.count)"
            )
        }

        let pwdData = Data(passphrase.utf8)
        // libargon2 rejects empty pwd; we already guard above for empty `passphrase`,
        // but utf8-encoded length could in principle be zero for some unicode edge
        // cases (it can't, actually — non-empty Swift String → non-empty utf8 bytes —
        // but we keep the explicit guard to make the precondition obvious).
        guard !pwdData.isEmpty else {
            throw BundleError.parameterOutOfBounds("passphrase utf-8 encoding produced zero bytes")
        }

        var keyBuffer = Data(count: keyLengthBytes)

        let result: Int32 = pwdData.withUnsafeBytes { pwdPtr in
            salt.withUnsafeBytes { saltPtr in
                keyBuffer.withUnsafeMutableBytes { keyPtr -> Int32 in
                    argon2id_hash_raw(
                        parameters.timeCost,
                        parameters.memoryKiB,
                        UInt32(parameters.parallelism),
                        pwdPtr.baseAddress,
                        pwdData.count,
                        saltPtr.baseAddress,
                        salt.count,
                        keyPtr.baseAddress,
                        keyLengthBytes
                    )
                }
            }
        }

        guard result == ARGON2_OK.rawValue else {
            throw BundleError.parameterOutOfBounds("argon2id_hash_raw failed with code \(result)")
        }

        return SymmetricKey(data: keyBuffer)
    }
}
