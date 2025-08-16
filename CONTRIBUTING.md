# Contributing Guide

Thanks for your interest in improving IT_Tools_GoLang!

## How to contribute
1. **Fork** the repo and create a feature branch.
2. Keep PRs focused; describe the motivation and behavior changes.
3. Ensure code builds and tests run locally:
   ```bash
   task fmt 
   task lint
   task test
   task vuln
   ```
4. Commit with a DCO sign-off:
```git
Signed-off-by: Your Name <you@example.com>
```
5. Open a Pull Request targeting `main`.

## Code style
* Use gofmt/gofumpt and organize imports.
* Prefer small, composable functions.
* Add table-driven tests where practical.
* Avoid introducing external dependencies unless clearly justified.

## Testing Guidelines
This project uses Go's standard testing tools and follows a specific naming convention to distinguish between internal (white-box) and API-level (black-box) tests.

-   **White-Box Tests:** To test unexported functions and internal logic, place your tests in a file ending with `_internal_test.go`. These tests are part of the main package (e.g., `package rateban`).

-   **Black-Box Tests:** To test the package's public API from a consumer's perspective, place your tests in a file ending with `_api_test.go`. These tests must be in an external test package (e.g., `package rateban_test`).

All contributions must include relevant tests and all tests must pass before a pull request will be merged.

## Licnese of contributions
By submitting a contribution, you agree that:
* Your contribution is licensed under AGPL-3.0-or-later (same as the project), and
* Per `[CLA.md](CLA.MD)`, you grant the maintainer a non-exclusive right to relicense your contribution as part of a dual-licensed distribution.

## Security
Please follow the guidance in `[SECURITY.md](SECURITY.md)`. Do not include secrets in PRs.

## Local development setup
- Go 1.24+  
- Recommended tools:
  - `staticcheck` — `go install honnef.co/go/tools/cmd/staticcheck@latest`
  - `gofumpt` — `go install mvdan.cc/gofumpt@latest` (or via VS Code Go extension)
  - github.com/go-chi/chi/v5 v5.2.2
  - github.com/joho/godotenv v1.5.1
  - golang.org/x/crypto v0.41.0
  - golang.org/x/mod v0.26.0
  - golang.org/x/net v0.42.0
  - golang.org/x/sync v0.16.0
  - golang.org/x/sys v0.35.0
  - golang.org/x/term v0.34.0
  - golang.org/x/text v0.28.0
  - golang.org/x/time v0.12.0
  - golang.org/x/tools v0.35.0
  - software.sslmate.com/src/go-pkcs12 v0.6.0

## DCO quickstart
Every commit must include a sign-off line:
```
+Signed-off-by: Your Name <you@example.com>
```
You can use `git commit -s` to add this automatically.
