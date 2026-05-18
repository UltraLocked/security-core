# UltraLocked Security Core

This repository contains the public security-critical components of UltraLocked.

UltraLocked is commercial iOS software funded by paid subscriptions. The full
App Store client, subscription UI, signing assets, provisioning profiles, and
operational deployment configuration are not included here. This repository is
for independent review of the portable encrypted bundle format, its tests, and
the written security model.

## What Is Included

- `UltraLockedFormat/`: Swift package for `.ultralocked` encrypted export
  bundles.
- `docs/`: threat model, format notes, security architecture, and non-goals.
- GitHub Actions workflow for Swift package tests.

## What Is Not Included

- The commercial iOS app shell and SwiftUI screens.
- Premium paywall and entitlement UI.
- App Store Connect configuration.
- Apple signing, provisioning, or deployment material.
- Marketing and outreach tooling.
- Backend infrastructure and production deployment state.

## Why This Is Public

Users should not need to trust marketing copy to evaluate core security claims.
The code in this repository lets reviewers inspect how export bundles are
constructed, how malformed input is rejected, and how tampering is detected.

## Quick Start

Run the Swift package tests:

```bash
swift test --package-path UltraLockedFormat --enable-code-coverage
```

## License

This repository is licensed under Apache-2.0.

The vendored Argon2 reference implementation in
`UltraLockedFormat/Sources/CArgon2` is dual licensed Apache-2.0 OR CC0-1.0 by
its upstream authors.

## Security Reports

Please see `SECURITY.md` before reporting vulnerabilities.
