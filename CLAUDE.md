# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`kubectl-rbac-why` is a kubectl plugin (Go, module `github.com/hardik/kubectl-rbac-why`) that traces *why* a Kubernetes RBAC permission is granted by walking the full Subject → Binding → Role → Rule chain. The binary is named `kubectl-rbac_why` (the underscore is required so kubectl resolves it as `kubectl rbac-why`).

## Common Commands

```bash
make build              # Build to ./bin/kubectl-rbac_why
make install            # Copy to $GOBIN
make kubectl-setup      # Build + install + verify kubectl plugin discovery
make run ARGS="..."     # Build then run with arguments

make fmt vet lint       # Code quality
make verify             # fmt + vet + lint + test (run before pushing)
make verify-deps        # Fail if go.mod/go.sum aren't tidy

make test               # Unit tests (go test -v -race -coverprofile=coverage.out ./pkg/...)
make test-coverage      # Generate coverage.html
make test-e2e           # E2E tests against current kubectl context
make e2e                # Full workflow: kind-create + build + setup-rbac + run e2e
make e2e-cleanup        # Delete the kind cluster

# Run a single test
go test -v -run TestRuleMatches ./pkg/rbac/
go test -v -run TestResolvePermission_GroupBinding ./pkg/rbac/
go test -v -run TestCanI_ServiceAccountGetSecrets ./test/e2e/
```

E2E tests look for the binary at `$RBAC_WHY_BINARY` or `../../bin/kubectl-rbac_why`. They `os.Exit(0)` (skip silently) if `kubectl cluster-info` fails, and apply `test/e2e/testdata/manifests/rbac-fixtures.yaml` against whatever the current context points at — point at a kind cluster before running. `make e2e` handles this end-to-end.

Toolchain: Go 1.25.5 (per `go.mod`; README says 1.21+ but go.mod is the source of truth), `golangci-lint` v1.55.2, `kind` v0.20.0. Install dev tools with `make tools`.

## Architecture

Layered, with a clear unidirectional dependency: `cmd → pkg/cmd/cani → {pkg/rbac, pkg/client, pkg/output}`. `pkg/rbac` and `pkg/client` have no dependency on `pkg/output` or `pkg/cmd`.

### Layers

- **`cmd/kubectl-rbac_why/main.go`** — thin entrypoint; wires `genericclioptions.IOStreams` and delegates to `cani.NewCmdRbacWhy`.
- **`pkg/cmd/cani/`** — Cobra command, option parsing, subject resolution from kubeconfig.
  - `cani.go` builds the command and orchestrates the flow in `Run`.
  - `options.go` parses flags, completes subject from current context (cert CN/O, token, exec, auth-provider), and parses `VERB RESOURCE` strings including subresources (`pods/exec`) and dotted API groups (`deployments.apps`).
  - `awsauth.go` reads the `kube-system/aws-auth` ConfigMap to map an IAM ARN → Kubernetes username/groups for EKS.
- **`pkg/client/`** — abstraction over the Kubernetes API (`RBACClient` interface). `K8sRBACClient` is the real impl; `MockRBACClient` is used by `pkg/rbac` unit tests. Only six methods: list/get for Roles, ClusterRoles, RoleBindings, ClusterRoleBindings.
- **`pkg/rbac/`** — pure RBAC logic, no I/O beyond the `RBACClient` interface.
  - `types.go`: `PermissionRequest`, `Subject`, `PermissionGrant`, `PermissionResult`, `RiskyPermission`.
  - `matcher.go`: `RuleMatches`, `SubjectMatches`, `SubjectMatchesWithGroups`, `GetImplicitGroups`.
  - `resolver.go`: `ParseSubject`, `Resolver.ResolvePermission` (single permission), `Resolver.ResolveAllPermissions` (all rules for a subject, used by `--show-risky`).
- **`pkg/output/`** — output rendering. `NewPrinter(format)` returns a `Printer` for `text|json|yaml|dot|mermaid`. `risky.go` defines `RiskyPatterns` and `AnalyzeRiskyPermissions`/`PrintRiskyPermissions` consumed when `--show-risky` is set.

### Resolution algorithm (key invariants)

1. `ParseSubject` splits on prefix: `system:serviceaccount:NS:NAME` → ServiceAccount; other `system:*` → Group; everything else → User.
2. `GetImplicitGroups` always adds `system:authenticated`; ServiceAccounts also get `system:serviceaccounts` and `system:serviceaccounts:<ns>`. Explicit groups (e.g. cert `O` fields, aws-auth `groups`) are merged in. **Group binding matches must consult this list, not just `subject.Groups` directly.**
3. `Resolver.ResolvePermission` always scans every `ClusterRoleBinding` (cluster-wide grants apply regardless of namespace), then — only if `request.Namespace != ""` — also scans `RoleBindings` in that namespace. A `RoleBinding` with `RoleRef.Kind == "ClusterRole"` references the ClusterRole's rules but produces a namespace-scoped grant (`ScopeNamespace`).
4. `RuleMatches` checks verb, API group, resource (with subresource handling), and resourceName independently. `*` is the wildcard for all three of verbs/apiGroups/resources. Resource matching also handles `pods/*` patterns. If a rule has `ResourceNames` but the request omits a resource name, the rule is treated as matching (a "could match" check).
5. The result returns **every** matching grant chain — duplicates across paths are intentional. Don't dedupe.

### Subject resolution from current context

When `--as` is omitted, `completeFromCurrentContext` extracts the user identity from kubeconfig:

- **Client certificate** (inline data or file path): parsed with `crypto/x509`; CN → username, O fields → groups.
- **Token / TokenFile**: cannot resolve identity locally, falls back to the kubeconfig `authInfo` name.
- **Exec auth**: detected as AWS (aws-iam-authenticator or `aws eks get-token`) or generic. For AWS, runs `aws sts get-caller-identity` (honoring `--profile`, exec args `-r/--role/--role-arn`, and exec env). If the exec config assumes a role, the username becomes `arn:aws:sts::ACCOUNT:assumed-role/ROLE-NAME` (no session suffix — used as the lookup key against `aws-auth`).
- **Auth provider** (oidc, gcp): cannot resolve, falls back to authInfo name.

For AWS IAM auth, after building the REST config, `Run` calls `ResolveAWSAuthIdentity` to map the IAM ARN through the `kube-system/aws-auth` ConfigMap (`mapRoles`/`mapUsers`) and rewrites `o.As` and `subject.Groups` to the mapped identity. If aws-auth isn't readable, it logs a warning and proceeds with the IAM ARN.

### Important: impersonation handling

`cani.Run` **deliberately clears** `ConfigFlags.Impersonate*` before building the REST config and restores them afterward. The Kubernetes client used to *read* RBAC objects must use the caller's real credentials, not impersonate the subject being investigated — otherwise the tool would be limited to whatever the subject itself can see. Don't "fix" this by removing the save/restore.

### Output formats

`text` (default, ASCII grant chains), `json`, `yaml`, `dot` (GraphViz, pipe through `dot -Tpng`), `mermaid`. The `Printer` interface receives an optional `*ContextInfo` that's only populated when `--as` is not provided (so output can show which kubeconfig context was used).

## Conventions

- **`pkg/rbac` stays I/O-free.** Everything goes through the `client.RBACClient` interface so tests can use `MockRBACClient`. Don't import `k8s.io/client-go` directly from `pkg/rbac`.
- **Subject equality for ServiceAccounts** requires matching `Kind + Name + Namespace`; for User/Group only `Kind + Name`. See `SubjectMatches`.
- **Wildcards** are constants from `k8s.io/api/rbac/v1`: `VerbAll`, `APIGroupAll`, `ResourceAll`. Use these rather than hardcoding `"*"`.
- **Tests**: unit tests live next to the code in `pkg/rbac/` and use table-driven style with `MockRBACClient`. E2E tests in `test/e2e/` shell out to the built binary and assert on stdout — they require a real cluster with `rbac-fixtures.yaml` applied.
- **Branch policy for this workspace**: develop on `claude/add-claude-documentation-XSFNS`; do not push elsewhere without explicit instruction.
