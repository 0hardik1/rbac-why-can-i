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
  - `options.go` parses flags, completes subject from current context (cert CN/O, token, exec, auth-provider), and parses `VERB RESOURCE [NAME]` including subresources (`pods/exec` or `--subresource`) and dotted API groups (`deployments.apps`). Note: unlike kubectl, the slash form means subresource; the resource name is the third positional arg.
  - `discovery.go` aligns the request with the cluster via API discovery: fills in the API group when omitted and clears the namespace for cluster-scoped resources. Degrades to a warning if discovery fails.
  - `selfsubject.go` resolves the authenticated identity via `SelfSubjectReview` when the kubeconfig can't (token/exec/OIDC auth); used whenever `ContextInfo.IdentityResolved` is false.
  - `awsauth.go` reads the `kube-system/aws-auth` ConfigMap to map an IAM ARN → Kubernetes username/groups for EKS. Malformed mapRoles/mapUsers YAML is an error, not a silent miss.
  - `ekspolicy.go` maps EKS access policies (AmazonEKSClusterAdminPolicy → cluster-admin rules, AmazonEKS{Admin,Edit,View}Policy → the matching ClusterRole fetched from the cluster, AmazonEKSAdminViewPolicy → read-all) into `PermissionGrant`s so access-policy-only admins aren't reported as denied. Unknown policies produce an error entry (incomplete result), never silence.
- **`pkg/client/`** — abstraction over the Kubernetes API (`RBACClient` interface). `K8sRBACClient` is the real impl; `MockRBACClient` is used by `pkg/rbac` unit tests. Only six methods: list/get for Roles, ClusterRoles, RoleBindings, ClusterRoleBindings.
- **`pkg/rbac/`** — pure RBAC logic, no I/O beyond the `RBACClient` interface.
  - `types.go`: `PermissionRequest`, `Subject`, `PermissionGrant`, `PermissionResult`, `RiskyPermission`.
  - `matcher.go`: `RuleMatches`, `SubjectMatches`, `SubjectMatchesWithGroups`, `GetImplicitGroups`.
  - `resolver.go`: `ParseSubject`, `Resolver.ResolvePermission` (single permission), `Resolver.ResolveAllPermissions` (all rules for a subject, used by `--show-risky`).
- **`pkg/output/`** — output rendering. `NewPrinter(format)` returns a `Printer` for `text|json|yaml|dot|mermaid`. `risky.go` defines `RiskyPatterns` and `AnalyzeRiskyPermissions`/`PrintRiskyPermissions` consumed when `--show-risky` is set.

### Resolution algorithm (key invariants)

1. `ParseSubject` splits on prefix: `system:serviceaccount:NS:NAME` → ServiceAccount; the well-known system groups (`system:masters`, `system:authenticated`, `system:unauthenticated`, `system:serviceaccounts[:<ns>]`, `system:nodes`, `system:bootstrappers[:...]`, `system:monitoring`) → Group; everything else, **including other `system:*` names** (`system:kube-scheduler`, `system:anonymous`, `system:node:<name>`) → User.
2. `GetImplicitGroups`: User/ServiceAccount subjects get `system:authenticated`, except the user `system:anonymous` which gets `system:unauthenticated`. ServiceAccounts also get `system:serviceaccounts` and `system:serviceaccounts:<ns>`. Group subjects get no implicit memberships. Explicit groups (cert `O` fields, `--as-group`, aws-auth/Access Entry groups) are merged in. **Group binding matches must consult this list, not just `subject.Groups` directly.**
3. The effective namespace mirrors kubectl: `-n` flag, else kubeconfig context namespace, else `default`; `applyDiscovery` then clears it for cluster-scoped resources and resolves the API group when omitted. `Resolver.ResolvePermission` always scans every `ClusterRoleBinding` (cluster-wide grants apply regardless of namespace), then (only if `request.Namespace != ""`) also scans `RoleBindings` in that namespace. A `RoleBinding` with `RoleRef.Kind == "ClusterRole"` references the ClusterRole's rules but produces a namespace-scoped grant (`ScopeNamespace`).
4. `RuleMatches` mirrors the upstream Kubernetes evaluator. `*` is the wildcard for verbs/apiGroups/resources; `*/subresource` matches that subresource on any resource; `pods/*` is NOT a wildcard. A rule with `ResourceNames` only matches when the request names one of those objects; a nameless request is NOT satisfied by it.
5. The result returns **every** matching grant chain; duplicates across paths are intentional. Don't dedupe. EKS access policy grants (Binding.Kind `EKSAccessEntry`, Role.Kind `EKSAccessPolicy`) are appended in `Run` after RBAC resolution.
6. `result.Errors` (unreadable Roles/ClusterRoles, unrecognized access policies) makes the result **incomplete**: text/dot/mermaid output must render INCOMPLETE instead of DENIED, JSON/YAML set `incomplete: true`, and `--show-risky` must not claim a clean result. Never present an incomplete resolution as a definitive denial.

### Subject resolution from current context

When `--as` is omitted, `completeFromCurrentContext` extracts the user identity from kubeconfig:

- **Client certificate** (inline data or file path): parsed with `crypto/x509`; CN → username, O fields → groups. Marked resolved.
- **Token / TokenFile / generic exec / auth provider (oidc, gcp)**: cannot resolve locally; `IdentityResolved` stays false and `Run` asks the API server via `SelfSubjectReview` (falling back to the authInfo name with a warning if that call fails).
- **AWS exec auth** (aws-iam-authenticator or `aws eks get-token`): runs `aws sts get-caller-identity` (honoring `--profile`, exec args `-r/--role/--role-arn`, and exec env). If the exec config assumes a role, the username becomes the assumed-role ARN synthesized from the **role ARN's own partition and account** (cross-account safe), with session name `EKSGetTokenAuth` appended for `aws eks get-token` (other tools: no session suffix; aws-auth matching uses prefix comparison).

For AWS IAM auth, `Run` walks Access Entry → aws-auth → raw ARN (`orchestrateAWSIdentity`). Pod Identity associations are informational only and never rewrite the identity. `--profile` is also injected into the kubeconfig's AWS exec plugin (`injectAWSProfile`) so the cluster client and the identity lookups use the same AWS principal. Access policies from a found Access Entry are carried in `ContextInfo.AccessPolicies` and folded into results via `accessPolicyGrants`.

### Important: impersonation handling

`cani.Run` **deliberately clears** `restConfig.Impersonate` right after `ToRESTConfig()`. The Kubernetes client used to *read* RBAC objects must use the caller's real credentials, not impersonate the subject being investigated; otherwise the tool would be limited to whatever the subject itself can see. Don't "fix" this by removing the clear. (It must be done on the built `rest.Config`, not by mutating `ConfigFlags` first: the flags' kubeconfig loader is cached with the original impersonation overrides.)

### Output formats

`text` (default, ASCII grant chains), `json`, `yaml`, `dot` (GraphViz, pipe through `dot -Tpng`), `mermaid`. The `Printer` interface receives an optional `*ContextInfo` that's only populated when `--as` is not provided (so output can show which kubeconfig context was used). YAML output goes through `sigs.k8s.io/yaml` so the json struct tags (names + omitempty) define the schema for both JSON and YAML; don't switch it back to a tag-unaware YAML encoder. Risky-pattern matching in `pkg/output/risky.go` only widens on **rule-side** wildcards; pattern values are literal targets (the cluster-admin pattern's `*` matches only rules that literally grant `*`).

## Conventions

- **`pkg/rbac` stays I/O-free.** Everything goes through the `client.RBACClient` interface so tests can use `MockRBACClient`. Don't import `k8s.io/client-go` directly from `pkg/rbac`.
- **Subject equality for ServiceAccounts** requires matching `Kind + Name + Namespace`; for User/Group only `Kind + Name`. See `SubjectMatches`.
- **Wildcards** are constants from `k8s.io/api/rbac/v1`: `VerbAll`, `APIGroupAll`, `ResourceAll`. Use these rather than hardcoding `"*"`.
- **Tests**: unit tests live next to the code in `pkg/rbac/` and use table-driven style with `MockRBACClient`. E2E tests in `test/e2e/` shell out to the built binary and assert on stdout — they require a real cluster with `rbac-fixtures.yaml` applied.
- **Branch policy for this workspace**: develop on `claude/add-claude-documentation-XSFNS`; do not push elsewhere without explicit instruction.
