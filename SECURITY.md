# Security Policy

## Supported versions
The main branch is supported.

## Reporting a vulnerability
Please email **<your-security-email-or-contact>** with:
- Description and impact
- Steps to reproduce or proof of concept
- Affected versions/commit

We will acknowledge receipt within 5 business days and coordinate a fix and disclosure timeline.

## Developer hygiene
Before pushing:
```bash
go vet ./...
staticcheck ./...
go test ./...
govulncheck ./...
```

Never commit secrets or private keys.
```yaml

---

# .gitignore (Go)

```gitignore
# Binaries
*.exe
*.exe~
*.dll
*.so
*.dylib
*.test

# Build output
/bin/
/out/
/dist/

# Coverage
*.cover
coverage.*
/coverage/

# Go workspaces
go.work
go.work.sum

# IDE/editor
.vscode/
.idea/
*.swp
.DS_Store

# Logs
*.log
```
