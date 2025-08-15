# IT_Tools_GoLang

[![CI](https://github.com/jsdraven/IT_Tools_GoLang/actions/workflows/ci.yml/badge.svg)](https://github.com/jsdraven/IT_Tools_GoLang/actions/workflows/ci.yml)

> Self-hosted web app written in Go. Community license: **AGPL-3.0-or-later**. Commercial licensing available for closed/proprietary deployments.

## Table of Contents
- [Overview](#overview)
- [Quick start](#quick-start)
- [Requirements](#requirements)
- [Security notes](#security-notes)
- [Development](#development)
- [go-task](#development-with-go-task)
- [Contributing](#contributing)
- [License](#license)
- [Accreditation](#accreditation)


## Overview
This project is designed to be self-hosted. Under **AGPL-3.0-or-later**, if you modify and run it as a network service, you must make the source code of your modified version available to users of that service. For organizations that cannot comply with AGPL terms, a separate commercial license is available from the maintainer.

## Quick start
```bash
task run
# this is shorthand for go run /cmd/server/main.go
# visit http://localhost:8080
```

## Requirements
* Go 1.24+
* Recommended: VS Code + Go extension (`gopls`, `dlv`, `gofumpt`, `staticcheck`)
* Git with SSH configured

## Security notes
Do not commit secrets (API keys, SSH keys, tokens).

Prefer owner-only permissions on private keys.

Run `govulncheck ./...` before pushing to identify known vulnerabilities.

## Development
**Status:** pre-alpha scaffolding.  
Local loop:
```bash
go fmt ./...
go vet ./...
staticcheck ./...
go test ./...
govulncheck ./...
```
Tip (Windows/VS Code): set Format on Save and organize imports; prefer `gofumpt`.

## Development with go-task

### Install tools once:
```bash
go install github.com/go-task/task/v3/cmd/task@latest
go install github.com/cosmtrek/air@latest
go install mvdan.cc/gofumpt@latest
go install honnef.co/go/tools/cmd/staticcheck@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
```
### Useful commands:
```bash
task tools      # install / upgrade tools
task dev        # hot reload with Air
task fmt        # format with gofumpt
task lint       # staticcheck
task test       # run tests
task vuln       # govulncheck
task build      # build
task release    # build an optimizd release binary
task clean      # clean caches
task cover      # Show total coverage in console
task cover-html # open HTML coverage
task precommit  # ryn checks before commiting (best used in git hook)
task run        # runs main package
```

## Licensing details (AGPL network use)
Under **AGPL-3.0-or-later**, if you deploy a **modified** version as a **network service**, you must make that modified source available to the service’s users. Commercial licensing is available if you cannot comply with AGPL obligations.

## SPDX headers
Add SPDX to Go files:
```go
// SPDX-License-Identifier: AGPL-3.0-or-later
```

## Contributing
Contributions are welcome! By submitting a PR you agree to:

License your contribution under AGPL-3.0-or-later (see `[LICENSE](LICENSE.md)`), and

The terms in `[CLA.md](CLA.md)` granting the maintainer limited relicensing rights for dual-licensed distributions.

Please include a DCO sign-off line in every commit:
```Git
Signed-off-by: Your Name <you@example.com>
```
See `[CONTRIBUTING.md](CONTRIBUTING.md)` for full details.

## License
*    Community: AGPL-3.0-or-later (see `[LICENSE](LICENSE.md)`)
*    Commercial: contact [jjustin@gmail.com](mailto:jjustin@gmail.com)

## Accreditation
This project benefited from assistance by ChatGPT (GPT-5 Thinking) from OpenAI for architecture discussion, documentation drafting, and code review suggestions. All final decisions and code are authored and reviewed by the maintainer. If you spot issues, please open an Issue or PR.
