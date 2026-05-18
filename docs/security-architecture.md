# Security Architecture

UltraLocked uses a commercial iOS client with a public, reviewable security
core. This repository covers the components whose behavior needs to be
independently inspectable.

## Public Components

### UltraLockedFormat

`UltraLockedFormat` defines `.ultralocked` encrypted bundles for cross-device
transfer and recovery.

The format is transport agnostic. A bundle can move through AirDrop, Files,
external storage, email, or another channel without trusting that channel for
confidentiality or integrity.

Core properties:

- Passphrase-derived master key using Argon2id.
- AES-256-GCM encryption via CryptoKit.
- HKDF-SHA256 domain separation for manifest and per-item keys.
- Header bytes authenticated as AES-GCM AAD.
- Item UUID authenticated as part of each item AAD.
- Hard parser limits before expensive work.
- Lazy item decryption after manifest unlock.

## Private Components

The following stay proprietary:

- Full iOS app shell and SwiftUI views.
- StoreKit purchase UX and paywall.
- Backend services.
- App signing and provisioning.
- Production deployment scripts and cloud account state.
- Marketing and outreach tools.

Those private components should not be required to evaluate the bundle format.

## Review Strategy

Reviewers should focus on:

- Whether malformed bundles fail closed.
- Whether tampering with header, manifest, item ciphertext, item nonce, item id,
  or auth tag is detected.
- Whether parser bounds prevent malicious resource exhaustion.
- Whether test vectors remain stable across releases.

## Important Limitations

This public repository does not prove the behavior of Apple's Secure Enclave,
iOS file protection, biometric policy, backend services, or the App Store
production environment. Those require device-level and operational testing
outside this repository.
