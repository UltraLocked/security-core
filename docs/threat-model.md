# Threat Model

This document describes the threat model for the components in this public
repository.

## Assets

Assets protected by the public security core:

- Plaintext vault item contents inside `.ultralocked` transfer bundles.
- Manifest metadata inside `.ultralocked` transfer bundles.
- Integrity of exported item records.

## In-Scope Attackers

The bundle format is designed to resist:

- An attacker who obtains a `.ultralocked` file but does not know the passphrase.
- An attacker who can modify bundle bytes before import.
- An attacker who tries to swap item ciphertexts inside a bundle.
- An attacker who crafts a malicious bundle to exhaust CPU, memory, or storage.

## Assumptions

The design assumes:

- The user's passphrase has enough entropy for the risk level.
- CryptoKit AES-GCM, HKDF-SHA256, and SHA-256 behave correctly.
- The vendored Argon2 reference implementation behaves correctly.
- The device used to decrypt the bundle is not fully compromised at the OS level.
- Production app builds protect local keys with iOS platform mechanisms outside
  this public package.

## Security Properties

Expected properties:

- Bundle contents are confidential without the passphrase.
- Any byte-level tampering of authenticated header, manifest, or item records is
  detected.
- Item records cannot be swapped between manifest entries without detection.
- Parser limits reject malicious sizes and KDF parameters before expensive work.

## Out Of Scope

This public repository does not claim to solve:

- A compromised iOS kernel or malicious device owner.
- Malware with screen, keyboard, or memory access while the app is unlocked.
- Weak or reused passphrases.
- Social engineering.
- Cloud backup exposure outside UltraLocked's control.
- Physical coercion or observation while secrets are visible.
- Availability if a user loses their passphrase.
- Correctness of private App Store configuration, backend services, or
  production cloud controls.
