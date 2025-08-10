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
