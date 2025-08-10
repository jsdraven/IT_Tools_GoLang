# Security Policy

## Supported versions
The `main` branch is supported.

## Reporting a vulnerability
Please email **[jjustin@gmail.com](mailto:jjustin@gmail.com)** with:
- A clear description of the issue and impact
- Steps to reproduce or proof-of-concept
- Affected versions/commit hash and environment details

We will acknowledge receipt within 5 business days and coordinate a fix and disclosure timeline.

## Developer hygiene
Before pushing:
```bash
go vet ./...
staticcheck ./...
go test ./...
govulncheck ./...
```

# Never commit secrets or private keys.

## Coordinated disclosure timeline (guideline)
1. Acknowledge receipt (≤ 5 business days).
2. Investigate and reproduce (target ≤ 10 business days).
3. Fix + prepare release notes.
4. Credit reporter (if desired) and disclose once a patched release is available, or after a mutually agreed window.
