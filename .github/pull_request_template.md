# Pull request

## Outcome and scope

<!-- State the user-visible or operational outcome. Name deliberate exclusions. -->

## Contract changes

<!-- List public behavior, flags, APIs, storage, migration, and compatibility impact. Write "None" only after checking each category. -->

## Security and network impact

<!-- Describe authority, profile policy, commands, processes, routes, DNS, HTTP exposure, authentication, secret handling, persistence, and rollback impact. -->

## Verification evidence

<!-- Report commands and observed results. Do not mark a gate passed from expectation or an unrelated artifact. -->

- [ ] Formatting and static checks pass: `gofmt`, `go vet ./...`, `git diff --check`, actionlint, and Markdown lint.
- [ ] Go tests pass shuffled and repeated; `go test -race -shuffle=on ./...` passes on amd64 CI.
- [ ] The exact command builds: `go build -trimpath -o tunnelfolio ./cmd/tunnelfolio`.
- [ ] Chromium and Firefox behavior/accessibility suites pass with zero applicable automated WCAG A/AA violations.
- [ ] Real OpenVPN and WireGuard namespace transitions pass when network behavior changes.
- [ ] Installer, systemd, cross-architecture, vulnerability, dependency-license, secret, and link gates pass.
- [ ] Every changed behavior is documented in the same pull request.
- [ ] No profile, key, certificate, credential, token, host detail, runtime state, generated binary, or workflow state is included.

## Rollout and rollback

<!-- Name the exact artifact, preconditions, forward checks, rollback trigger, absence proof, and any deferred external gate. -->
