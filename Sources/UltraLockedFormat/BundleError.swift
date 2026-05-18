import Foundation

/// Errors produced when parsing, building, or validating an UltraLocked bundle.
public enum BundleError: Error, Equatable, CustomStringConvertible {
    case invalidHeader(String)
    case unsupportedVersion(UInt16)
    case unsupportedKDF(UInt8)
    case parameterOutOfBounds(String)
    case decryptionFailed
    case manifestParseFailed(String)
    case truncated(expected: Int, actual: Int)

    public var description: String {
        switch self {
        case .invalidHeader(let message): return "Invalid bundle header: \(message)"
        case .unsupportedVersion(let v): return "Unsupported bundle version: \(v)"
        case .unsupportedKDF(let id): return "Unsupported KDF id: \(id)"
        case .parameterOutOfBounds(let message): return "Parameter out of bounds: \(message)"
        case .decryptionFailed: return "Decryption failed (authentication tag mismatch or wrong key)"
        case .manifestParseFailed(let message): return "Manifest parse failed: \(message)"
        case .truncated(let expected, let actual): return "Truncated input: expected \(expected) bytes, got \(actual)"
        }
    }
}
