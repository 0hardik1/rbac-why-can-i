# kubectl rbac-why

A kubectl plugin that explains **WHY** a permission is granted in Kubernetes RBAC by showing the exact Role/ClusterRole + Binding chain.

## Quick Example

### Using Current Context (--as not required)

```bash
kubectl rbac-why can-i get secrets -n default
```

```
Using current context:
  Context:  my-cluster-admin
  Cluster:  my-cluster
  User:     admin@example.com

ALLOWED: User admin@example.com can get secrets in namespace default

Permission granted through 1 path(s):

Path 1:
  Subject: User admin@example.com
      |
      v
  ClusterRoleBinding: cluster-admin-binding
      |
      v
  ClusterRole: cluster-admin
      |
      v
  Rule: apiGroups=["*"], resources=[*], verbs=[*]
  Scope: cluster-wide
```

### Checking a Specific Subject

```bash
kubectl rbac-why can-i --as system:serviceaccount:default:my-sa get secrets -n default
```

```
ALLOWED: ServiceAccount default/my-sa can get secrets in namespace default

Permission granted through 1 path(s):

Path 1:
  Subject: ServiceAccount default/my-sa
      |
      v
  RoleBinding: my-sa-secret-reader (namespace: default)
      |
      v
  Role: secret-reader (namespace: default)
      |
      v
  Rule: apiGroups=[""], resources=[secrets], verbs=[get, list, watch]
  Scope: namespace
```

### Multiple Grant Paths

When a permission is granted through multiple roles, all paths are shown:

```bash
kubectl rbac-why can-i --as system:serviceaccount:default:admin-sa get pods -n default
```

```
ALLOWED: ServiceAccount default/admin-sa can get pods in namespace default

Permission granted through 3 path(s):

Path 1:
  Subject: ServiceAccount default/admin-sa
      |
      v
  RoleBinding: admin-sa-pod-reader (namespace: default)
      |
      v
  Role: pod-reader (namespace: default)
      |
      v
  Rule: apiGroups=[""], resources=[pods], verbs=[get, list, watch]
  Scope: namespace

Path 2:
  Subject: ServiceAccount default/admin-sa
      |
      v
  RoleBinding: admin-sa-edit (namespace: default)
      |
      v
  ClusterRole: edit
      |
      v
  Rule: apiGroups=[""], resources=[pods], verbs=[get, list, watch, create, update, patch, delete]
  Scope: namespace

Path 3:
  Subject: ServiceAccount default/admin-sa
      |
      v
  ClusterRoleBinding: admin-sa-cluster-view
      |
      v
  ClusterRole: view
      |
      v
  Rule: apiGroups=[""], resources=[pods], verbs=[get, list, watch]
  Scope: cluster-wide
```

## Why This Tool?

Kubernetes RBAC can become incredibly difficult to debug as clusters grow in complexity:

- **Multiple roles per subject**: A single ServiceAccount may have permissions granted through numerous Roles and ClusterRoles, each attached via different bindings. When troubleshooting why a pod can (or cannot) perform an action, manually tracing through dozens of bindings is tedious and error-prone.

- **Implicit group memberships**: ServiceAccounts automatically belong to groups like `system:serviceaccounts` and `system:serviceaccounts:<namespace>`. Permissions granted to these groups apply to all ServiceAccounts, making it easy to miss where a permission actually comes from.

- **ClusterRoles referenced by RoleBindings**: A RoleBinding can reference a ClusterRole (not just a Role), granting cluster-defined permissions within a specific namespace. This indirection adds another layer of complexity when auditing permissions.

- **Wildcard rules**: Roles with `*` verbs, `*` resources, or `*` API groups can grant broad permissions that aren't obvious from a quick inspection.

- **No built-in "why" explanation**: While `kubectl auth can-i` tells you whether a permission is allowed, it doesn't explain *which* role granted it or *how* the subject is bound to that role.

This tool answers the question: **"Why can this subject perform this action?"** by tracing the complete permission grant chain from subject → binding → role → rule.

## Installation

```bash
# Build, install to GOBIN, and verify kubectl plugin discovery
make kubectl-setup

# The plugin is now available as:
kubectl rbac-why can-i --as <subject> <verb> <resource>
```

If you'd rather run the steps manually:

```bash
make build      # build to ./bin/kubectl-rbac_why
make install    # copy to $GOBIN
```

`$GOBIN` (or `$GOPATH/bin`) must be on your `PATH` for kubectl to discover the plugin.

## Usage

### Basic Syntax

```bash
# Using current kubeconfig context (recommended for checking your own permissions)
kubectl rbac-why can-i <verb> <resource> [name] [-n namespace]

# Check permissions for a specific subject
kubectl rbac-why can-i --as <subject> [--as-group <group>] <verb> <resource> [name] [-n namespace]
```

Namespace resolution follows kubectl: the `-n` flag wins, then the kubeconfig context's namespace, then `default`. For cluster-scoped resources (nodes, persistentvolumes, ...) the namespace is ignored; the tool checks the resource's scope and API group via API discovery, so `get deployments` resolves to the `apps` group without spelling out `deployments.apps`.

### Check Your Own Permissions

```bash
# Can I get secrets in the default namespace?
kubectl rbac-why can-i get secrets -n default

# Can I create deployments?
kubectl rbac-why can-i create deployments.apps -n my-namespace
```

### Check Cluster-Wide Permissions

```bash
kubectl rbac-why can-i list nodes
kubectl rbac-why can-i --as system:serviceaccount:kube-system:admin list nodes
```

### Check Subresource Access

```bash
kubectl rbac-why can-i create pods/exec -n default
kubectl rbac-why can-i --as system:serviceaccount:default:debug-sa create pods/exec -n default

# kubectl-style flag form is also accepted
kubectl rbac-why can-i get pods --subresource=log -n default
```

Note: unlike `kubectl auth can-i`, the slash form here means RESOURCE/SUBRESOURCE, not RESOURCE/NAME. Pass the resource name as a separate argument (below).

### Check Access to a Named Object (resourceNames)

RBAC rules with `resourceNames` only grant access to those specific objects. A request without a name asks about the resource in general and is NOT satisfied by such rules:

```bash
# Denied if the only rule is restricted to resourceNames: ["db-password"]
kubectl rbac-why can-i --as jane get secrets -n default

# Allowed: the named request matches the resourceNames rule
kubectl rbac-why can-i --as jane get secrets db-password -n default
```

### Output Formats

```bash
# JSON output (includes context info when --as is not provided)
kubectl rbac-why can-i get pods -o json

# YAML output
kubectl rbac-why can-i get pods -o yaml

# GraphViz DOT format (pipe to dot for visualization)
kubectl rbac-why can-i get pods -o dot | dot -Tpng > rbac.png

# Mermaid diagram format
kubectl rbac-why can-i get pods -o mermaid
```

### EKS / AWS Authentication

`kubectl rbac-why` talks to your cluster through the active kubeconfig context. On EKS, that context typically uses `aws eks get-token` as exec-auth, which needs working AWS credentials — and the plugin itself also calls EKS APIs (Access Entries, Pod Identity) to enrich its output.

If you have more than one AWS profile configured (the common case), **export `AWS_PROFILE` before running the plugin** so both `aws eks get-token` / `aws sts get-caller-identity` and the plugin's own EKS API calls pick the right credentials:

```bash
export AWS_PROFILE=my-eks-profile
kubectl rbac-why can-i get secrets -n default
```

Or pass `--profile` (`-p`) per invocation:

```bash
kubectl rbac-why can-i -p my-eks-profile get secrets -n default
```

Without a usable profile, the plugin falls back to the kubeconfig user name and skips EKS-side identity lookups; basic RBAC tracing still works, but the output won't include EKS Access Entry / Pod Identity context.

### Risky Permissions Analysis

Analyze permissions for potentially dangerous patterns:

```bash
# Analyze your own risky permissions
kubectl rbac-why can-i --show-risky -n default

# Analyze a specific subject's risky permissions
kubectl rbac-why can-i --as system:serviceaccount:default:my-sa --show-risky -n default
```

This detects risky permissions such as:
- Secrets access
- Pod exec/attach
- Pod creation (privilege escalation vector)
- Impersonation
- Node proxy access
- Role/binding modification (including the `escalate` and `bind` verbs)
- Wildcard permissions (cluster-admin equivalent)

On EKS, permissions granted through EKS access policies attached to the caller's Access Entry are included in the analysis. If some RBAC objects cannot be read, the report is labeled incomplete instead of claiming a clean result.

## Development

### Prerequisites

- Go 1.25+
- kubectl configured with a cluster
- kind (for e2e tests)

### Building

```bash
# Download dependencies
make deps

# Build the binary
make build

# Run tests
make test

# Run linter
make lint

# Run all verification
make verify
```

### Testing

```bash
# Unit tests
make test

# E2E tests (requires a running cluster)
make test-e2e

# Create a kind cluster for testing
make kind-create

# Setup test RBAC resources
make kind-setup-rbac

# Run a manual test
make kind-test

# Cleanup
make kind-delete
```

### Makefile Targets

```
Development:
  build                Build the binary
  install              Install to GOBIN
  run                  Run the plugin with ARGS
  fmt                  Format code
  vet                  Run go vet
  lint                 Run golangci-lint

Testing:
  test                 Run unit tests
  test-coverage        Show test coverage
  test-e2e             Run e2e tests
  test-all             Run all tests

Dependencies:
  deps                 Download dependencies
  tools                Install development tools

Kind Cluster:
  kind-create          Create a kind cluster
  kind-delete          Delete the kind cluster
  kind-setup-rbac      Setup test RBAC resources

Verification:
  verify               Run all verification checks
  clean                Clean build artifacts
```

## How It Works

The tool uses a multi-step resolution algorithm to trace permissions from subject to rule:

### Step 1: Parse the Subject

The `--as` flag is parsed to determine the subject type:

| Input Format | Subject Type | Example |
|--------------|--------------|---------|
| `system:serviceaccount:<ns>:<name>` | ServiceAccount | `system:serviceaccount:default:my-sa` |
| Well-known system groups (`system:masters`, `system:authenticated`, `system:unauthenticated`, `system:serviceaccounts`, `system:serviceaccounts:<ns>`, `system:nodes`, `system:bootstrappers[:...]`, `system:monitoring`) | Group | `system:masters` |
| Everything else, including other `system:*` identities | User | `jane@example.com`, `system:kube-scheduler`, `system:anonymous`, `system:node:<name>` |

When `--as` is not given and the kubeconfig uses token, exec, or OIDC authentication, the tool asks the API server for the authenticated username and groups via a `SelfSubjectReview` instead of guessing from the kubeconfig entry name.

### Step 2: Compute Implicit Group Memberships

Before searching for bindings, the tool computes all groups the subject implicitly belongs to:

- **Authenticated users and ServiceAccounts**: `system:authenticated`
- **The `system:anonymous` user**: `system:unauthenticated` (never `system:authenticated`)
- **All ServiceAccounts**: `system:serviceaccounts`
- **ServiceAccounts in a namespace**: `system:serviceaccounts:<namespace>`
- **Group subjects**: no implicit memberships; the group name itself is matched against binding subjects

For example, `system:serviceaccount:default:my-sa` belongs to:
- `system:authenticated`
- `system:serviceaccounts`
- `system:serviceaccounts:default`

This is critical because bindings that target these groups will also grant permissions to the subject. Explicit groups (client-certificate `O` fields, `--as-group`, aws-auth or Access Entry groups) are merged in as well.

### Step 3: Search ClusterRoleBindings

The tool lists **all ClusterRoleBindings** in the cluster and checks each one:

1. Iterate through the binding's `subjects` list
2. For each subject in the binding, check if it matches:
   - **Direct match**: Same kind, name, and namespace (for ServiceAccounts)
   - **Group match**: Binding targets a Group that the subject belongs to (including implicit groups)

If the binding matches, the tool fetches the referenced **ClusterRole** and proceeds to rule matching.

### Step 4: Search RoleBindings (Namespace-Scoped)

For namespaced requests (the effective namespace is the `-n` flag, else the kubeconfig context namespace, else `default`), the tool also lists **RoleBindings in that namespace**:

1. Same subject matching logic as ClusterRoleBindings
2. RoleBindings can reference either:
   - A **Role** in the same namespace
   - A **ClusterRole** (permissions are scoped to the namespace)

This distinction matters: a ClusterRole referenced by a RoleBinding grants its permissions only within that namespace, not cluster-wide.

### Step 5: Match Permission Rules

For each Role/ClusterRole found through matching bindings, the tool examines every `PolicyRule`:

```
rule matches if ALL of the following are true:
├── Verb matches (rule.verbs contains request.verb OR "*")
├── API Group matches (rule.apiGroups contains request.apiGroup OR "*")
├── Resource matches (rule.resources contains request.resource, "*", or "*/subresource")
│   └── Subresources: "pods/exec" matches "pods/exec", "*/exec", or "*"
└── ResourceNames: a rule with resourceNames only matches when the request
    names one of those objects; a request without a name is not satisfied
```

**Wildcard handling** (mirrors the upstream Kubernetes RBAC evaluator):
- `*` in verbs matches any verb
- `*` in apiGroups matches any API group
- `*` in resources matches any resource and subresource
- `*/scale` matches the `scale` subresource on any resource
- `pods/*` is NOT a wildcard in Kubernetes and is not treated as one

### Step 6: Build Grant Chains

For every matching rule, the tool records the complete **grant chain**:

```
Subject
   ↓
Binding (RoleBinding or ClusterRoleBinding)
   ↓
Role (Role or ClusterRole)
   ↓
PolicyRule (the specific rule that grants the permission)
```

All matching chains are returned, showing **every path** by which the permission is granted. This is important because:
- A permission may be granted multiple times through different roles
- Removing one binding might not revoke access if another path exists
- Understanding all grant paths is essential for proper RBAC auditing

### Resolution Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         PERMISSION RESOLUTION                           │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Input: Subject + Verb + Resource + Namespace                           │
│                                                                         │
│  ┌─────────────────┐                                                    │
│  │  Parse Subject  │ ──→ Determine: User / Group / ServiceAccount       │
│  └────────┬────────┘                                                    │
│           │                                                             │
│           ▼                                                             │
│  ┌─────────────────┐     ┌──────────────────────────────────────────┐   │
│  │ Compute Groups  │ ──→ │ system:authenticated                     │   │
│  └────────┬────────┘     │ system:serviceaccounts                   │   │
│           │              │ system:serviceaccounts:<ns>              │   │
│           │              └──────────────────────────────────────────┘   │
│           ▼                                                             │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                  For each ClusterRoleBinding                    │    │
│  │  ┌───────────────────────────────────────────────────────────┐  │    │
│  │  │ Does binding.subjects contain Subject OR Subject's group? │  │    │
│  │  └─────────────────────────┬─────────────────────────────────┘  │    │
│  │                            │ Yes                                │    │
│  │                            ▼                                    │    │
│  │  ┌───────────────────────────────────────────────────────────┐  │    │
│  │  │            Fetch ClusterRole (binding.roleRef)            │  │    │
│  │  └─────────────────────────┬─────────────────────────────────┘  │    │
│  │                            │                                    │    │
│  │                            ▼                                    │    │
│  │  ┌───────────────────────────────────────────────────────────┐  │    │
│  │  │    For each rule: Does rule grant requested permission?   │  │    │
│  │  │    (verb + apiGroup + resource + subresource match)       │  │    │
│  │  └─────────────────────────┬─────────────────────────────────┘  │    │
│  │                            │ Yes                                │    │
│  │                            ▼                                    │    │
│  │                    Record Grant Chain                           │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │          For each RoleBinding (in target namespace)             │    │
│  │                      (same logic as above)                      │    │
│  │  Note: RoleBinding can reference Role OR ClusterRole            │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
│  Output: All Grant Chains (Subject → Binding → Role → Rule)             │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## License

MIT
