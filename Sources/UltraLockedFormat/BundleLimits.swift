import Foundation

/// Hard caps on parser inputs to prevent resource-exhaustion attacks from a malicious `.ultralocked` file.
/// Validated before any expensive work is performed.
public enum BundleLimits {

    // MARK: Argon2id

    /// Minimum allowed Argon2id `time_cost` parameter (iterations).
    public static let argon2TimeCostMin: UInt32 = 1
    /// Maximum allowed Argon2id `time_cost` parameter. Bounds CPU work per unlock attempt.
    public static let argon2TimeCostMax: UInt32 = 10

    /// Minimum allowed Argon2id `memory_kib` parameter (the spec floor is 8).
    public static let argon2MemoryKiBMin: UInt32 = 8
    /// Maximum allowed Argon2id `memory_kib` parameter. Bounds RAM allocation at parse time (256 MiB).
    public static let argon2MemoryKiBMax: UInt32 = 256 * 1024

    /// Minimum allowed Argon2id `parallelism` (lanes).
    public static let argon2ParallelismMin: UInt8 = 1
    /// Maximum allowed Argon2id `parallelism`. Bounds thread fan-out.
    public static let argon2ParallelismMax: UInt8 = 8

    // MARK: Sizes

    /// Maximum length of the encrypted manifest, in bytes (1 MiB).
    public static let manifestSizeMax: UInt32 = 1 * 1024 * 1024

    /// Maximum length of any single encrypted item record, in bytes (250 MiB).
    public static let itemSizeMax: UInt64 = 250 * 1024 * 1024

    /// Maximum total file size, in bytes (2 GiB).
    public static let totalFileSizeMax: UInt64 = 2 * 1024 * 1024 * 1024

    // MARK: Validators

    public static func validateArgon2Params(timeCost: UInt32, memoryKiB: UInt32, parallelism: UInt8) throws {
        guard (argon2TimeCostMin...argon2TimeCostMax).contains(timeCost) else {
            throw BundleError.parameterOutOfBounds(
                "argon2.time_cost \(timeCost) outside [\(argon2TimeCostMin), \(argon2TimeCostMax)]"
            )
        }
        guard (argon2MemoryKiBMin...argon2MemoryKiBMax).contains(memoryKiB) else {
            throw BundleError.parameterOutOfBounds(
                "argon2.memory_kib \(memoryKiB) outside [\(argon2MemoryKiBMin), \(argon2MemoryKiBMax)]"
            )
        }
        guard (argon2ParallelismMin...argon2ParallelismMax).contains(parallelism) else {
            throw BundleError.parameterOutOfBounds(
                "argon2.parallelism \(parallelism) outside [\(argon2ParallelismMin), \(argon2ParallelismMax)]"
            )
        }
    }

    public static func validateManifestSize(_ size: UInt32) throws {
        guard size <= manifestSizeMax else {
            throw BundleError.parameterOutOfBounds("manifest_size \(size) > max \(manifestSizeMax)")
        }
    }

    public static func validateItemSize(_ size: UInt64) throws {
        guard size <= itemSizeMax else {
            throw BundleError.parameterOutOfBounds("item_size \(size) > max \(itemSizeMax)")
        }
    }

    public static func validateTotalFileSize(_ size: UInt64) throws {
        guard size <= totalFileSizeMax else {
            throw BundleError.parameterOutOfBounds("total file size \(size) > max \(totalFileSizeMax)")
        }
    }
}
