# IT_Tools_GoLang
> Self-hosted web app written in Go. Licensed AGPL-3.0 for community use; commercial licensing available for closed/proprietary deployments.

## Overview
This project is designed to be self-hosted. Under **AGPL-3.0**, if you modify and run it as a network service, you must make the source code of your modified version available to its users. Commercial licensing is available if you need to combine or deploy this project without AGPL obligations.

## Quick start
```bash
go run .
# then visit http://localhost:8080
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

pgsql
Copy
Edit
Signed-off-by: Your Name <you@example.com>
See CONTRIBUTING.md for full details.

License
Community: AGPL-3.0-only (see LICENSE)

Commercial: Contact the maintainer at <your-email-or-contact-link> to discuss a commercial license if you cannot comply with the AGPL (e.g., you want to keep changes private).

Accreditation
This project benefited from assistance by ChatGPT (GPT-5 Thinking) from OpenAI for architecture notes, documentation drafting, and code review suggestions. All final decisions and code are authored and reviewed by the maintainer. AI-generated suggestions may contain errors; please open issues for corrections.

Acknowledgments
Go Team for the Go toolchain and VS Code extension.

yaml
Copy
Edit

---

# CONTRIBUTING.md

```markdown
# Contributing Guide

Thanks for your interest in contributing!

## How to contribute
1. Fork the repo and create a feature branch.
2. Write clear, tested code. Run:
   ```bash
   go fmt ./...
   go vet ./...
   staticcheck ./...
   go test ./...
   govulncheck ./...
Commit with a DCO sign-off:

pgsql
Copy
Edit
Signed-off-by: Your Name <you@example.com>
Open a Pull Request describing the change and its motivation.

Code style
Use gofmt/gofumpt and organize imports.

Keep functions small and focused; add table-driven tests where practical.

License of contributions
By submitting a contribution, you agree that:

Your contribution is licensed under AGPL-3.0 (same as the project), and

You grant the maintainer a non-exclusive right to relicense your contribution as part of a dual-licensed offering (see CLA.md).

If this is problematic for your employer, please coordinate with them before contributing.

Reporting security issues
Please do not file public issues for vulnerabilities. Follow the instructions in SECURITY.md.

yaml
Copy
Edit

---

# CLA.md (lightweight, individual + entity compatible)

```markdown
# Contributor License Terms (Lightweight)

By submitting a contribution (code, documentation, or other material) to this project (“Project”), you agree:

1. **License to Project**. You license your contribution under the Project’s open-source license (AGPL-3.0) so it can be used in the community edition.

2. **Additional Relicensing Permission**. You grant the Project maintainer a perpetual, worldwide, non-exclusive, no-charge license to relicense your contribution as part of a dual-licensed distribution (e.g., under a commercial license) without additional permission from you.

3. **Originality / Rights**. You represent that you have the right to submit the contribution (it is your original work, or you have the necessary rights), and that you are not knowingly infringing third-party rights.

4. **No Warranty**. Contributions are provided “as is” without warranties.

If you contribute on behalf of an employer or entity, you confirm you are authorized to grant these rights.
