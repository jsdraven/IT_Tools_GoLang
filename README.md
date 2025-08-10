# IT_Tools_GoLang

[![CI](https://github.com/jsdraven/IT_Tools_GoLang/actions/workflows/ci.yml/badge.svg)](https://github.com/jsdraven/IT_Tools_GoLang/actions/workflows/ci.yml)

> Self-hosted web app written in Go. Community license: **AGPL-3.0-or-later**. Commercial licensing available for closed/proprietary deployments.

## Overview
This project is designed to be self-hosted. Under **AGPL-3.0-or-later**, if you modify and run it as a network service, you must make the source code of your modified version available to users of that service. For organizations that cannot comply with AGPL terms, a separate commercial license is available from the maintainer.

## Quick start
```bash
go run .
# visit http://localhost:8080
```
## Requirements
Go 1.24+

Recommended: VS Code + Go extension (<mark>gopls</mark>, <mark>dlv</mark>, <mark>gofumpt</mark>, <mark>staticcheck</mark>)

Git with SSH configured

## Security notes
Do not commit secrets (API keys, SSH keys, tokens).

Prefer owner-only permissions on private keys.

Run <mark>govulncheck ./...</mark> before pushing to identify known vulnerabilities.

## Contributing
Contributions are welcome! By submitting a PR you agree to:

License your contribution under AGPL-3.0-or-later (see <mark> [LICENSE](LICENSE.md) </mark>), and

The terms in <mark> [CLA.md](CLA.md) </mark> granting the maintainer limited relicensing rights for dual-licensed distributions.

Please include a DCO sign-off line in every commit:
```Git
Signed-off-by: Your Name <you@example.com>
```
See <mark> [CONTRIBUTING.md](CONTRIBUTING.md) </mark> for full details.

## License
*    Community: AGPL-3.0-or-later (see <mark> [LICENSE](LICENSE.md) </mark>)
*    Commercial: contact [jjustin@gmail.com](mailto:jjustin@gmail.com)

## Accreditation
This project benefited from assistance by ChatGPT (GPT-5 Thinking) from OpenAI for architecture discussion, documentation drafting, and code review suggestions. All final decisions and code are authored and reviewed by the maintainer. If you spot issues, please open an Issue or PR.
