import Foundation
import Security

/// Cryptographically-secure random byte generation. Backed by `SecRandomCopyBytes`.
internal enum Random {

    /// Returns `count` cryptographically random bytes. Traps on system RNG failure
    /// (which would be a catastrophic platform error that no caller can recover from).
    static func bytes(_ count: Int) -> Data {
        precondition(count >= 0)
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { buf -> Int32 in
            guard let base = buf.baseAddress else { return errSecAllocate }
            return SecRandomCopyBytes(kSecRandomDefault, count, base)
        }
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed: status=\(status)")
        return data
    }
}
