# Contributing

Security-focused contributions are welcome.

Good contributions include:

- Parser hardening.
- Additional malformed bundle tests.
- Interoperability test vectors.
- Documentation corrections.

Please avoid changes that add production deployment credentials, app signing
material, analytics, or commercial app code. This repository intentionally stays
small so reviewers can audit the security core without unrelated product code.

Before opening a pull request, run:

```bash
swift test --package-path UltraLockedFormat --enable-code-coverage
```
