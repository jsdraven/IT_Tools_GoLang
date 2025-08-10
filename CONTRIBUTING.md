# Contributing Guide

Thanks for your interest in improving IT_Tools_GoLang!

## How to contribute
1. **Fork** the repo and create a feature branch.
2. Keep PRs focused; describe the motivation and behavior changes.
3. Ensure code builds and tests run locally:
   ```bash
   go fmt ./...
   go vet ./...
   staticcheck ./...
   go test ./...
   govulncheck ./...
   ```
4. Commit with a DCO sign-off:
```git
Signed-off-by: Your Name <you@example.com>
```
5. Open a Pull Request targeting <mark> main </mark>.

## Local development setup
- Go 1.24+  
- Recommended tools:
  - `staticcheck` — `go install honnef.co/go/tools/cmd/staticcheck@latest`
  - `gofumpt` — `go install mvdan.cc/gofumpt@latest` (or via VS Code Go extension)

## DCO quickstart
Every commit must include a sign-off line:
```
+Signed-off-by: Your Name <you@example.com>
```
You can use `git commit -s` to add this automatically.

## Code style
* Use gofmt/gofumpt and organize imports.
* Prefer small, composable functions.
* Add table-driven tests where practical.
* Avoid introducing external dependencies unless clearly justified.

## Licnese of contributions
By submitting a contribution, you agree that:
* Your contribution is licensed under AGPL-3.0-or-later (same as the project), and
* Per <mark> [CLA.md](CLA.MD) </mark>, you grant the maintainer a non-exclusive right to relicense your contribution as part of a dual-licensed distribution.

## Security
Please follow the guidance in <mark> [SECURITY.md](SECURITY.md) </mark>. Do not include secrets in PRs.
