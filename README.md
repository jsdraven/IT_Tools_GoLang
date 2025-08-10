# IT_Tools_GoLang
> Self-hosted web app written in Go. Licensed AGPL-3.0 for community use; commercial licensing available for closed/proprietary deployments.

## Overview
This project is designed to be self-hosted. Under **AGPL-3.0**, if you modify and run it as a network service, you must make the source code of your modified version available to its users. Commercial licensing is available if you need to combine or deploy this project without AGPL obligations.

## Quick start
```bash
go run .
# then visit http://localhost:8080
```

Requirements
Go 1.24+

Recommended: VS Code + Go extension (gopls, dlv, gofumpt, staticcheck)

Git with SSH key configured (e.g., host alias github.com-personal in ~/.ssh/config)

Security notes
Never commit secrets (API keys, SSH keys, tokens).

Run govulncheck ./... before pushing; see Security Policy for details.

Private keys should be owner-read only; avoid broad ACLs/permissions.

Contributing
Contributions are welcome! By submitting a PR you agree to:

License your contribution under AGPL-3.0 (see LICENSE), and

The simple Contributor License terms in CLA.md that allow the maintainer to offer dual-licensing.

Please also add a DCO sign-off to each commit:

```git
Signed-off-by: Your Name <you@example.com>
```
See [CONTRIBUTING.md](contributing.md) for full details.

License
Community: AGPL-3.0-only (see [LICENSE](SECURITY.md))

Commercial: Contact the maintainer at jjustin@gmail.com to discuss a commercial license if you cannot comply with the AGPL (e.g., you want to keep changes private).

Accreditation
This project benefited from assistance by ChatGPT (GPT-5 Thinking) from OpenAI for architecture notes, documentation drafting, and code review suggestions. All final decisions and code are authored and reviewed by the maintainer. AI-generated suggestions may contain errors; please open issues for corrections.

Acknowledgments
Go Team for the Go toolchain and VS Code extension.


