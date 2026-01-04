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
# Build from source
make build

# Install to GOBIN
make install

# The plugin is now available as:
kubectl rbac-why can-i --as <subject> <verb> <resource>
```

## Usage

### Basic Syntax

```bash
# Using current kubeconfig context (recommended for checking your own permissions)
kubectl rbac-why can-i <verb> <resource> [-n namespace]

# Check permissions for a specific subject
kubectl rbac-why can-i --as <subject> <verb> <resource> [-n namespace]
```

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
- Role/binding modification
- Wildcard permissions (cluster-admin equivalent)

## Development

### Prerequisites

- Go 1.21+
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
| `system:*` (other patterns) | Group | `system:masters` |
| Everything else | User | `jane@example.com` |

### Step 2: Compute Implicit Group Memberships

Before searching for bindings, the tool computes all groups the subject implicitly belongs to:

- **All authenticated subjects**: `system:authenticated`
- **All ServiceAccounts**: `system:serviceaccounts`
- **ServiceAccounts in a namespace**: `system:serviceaccounts:<namespace>`

For example, `system:serviceaccount:default:my-sa` belongs to:
- `system:authenticated`
- `system:serviceaccounts`
- `system:serviceaccounts:default`

This is critical because bindings that target these groups will also grant permissions to the subject.

### Step 3: Search ClusterRoleBindings

The tool lists **all ClusterRoleBindings** in the cluster and checks each one:

1. Iterate through the binding's `subjects` list
2. For each subject in the binding, check if it matches:
   - **Direct match**: Same kind, name, and namespace (for ServiceAccounts)
   - **Group match**: Binding targets a Group that the subject belongs to (including implicit groups)

If the binding matches, the tool fetches the referenced **ClusterRole** and proceeds to rule matching.

### Step 4: Search RoleBindings (Namespace-Scoped)

If a namespace is specified in the request, the tool also lists **RoleBindings in that namespace**:

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
├── Resource matches (rule.resources contains request.resource OR "*")
│   └── Handles subresources: "pods/exec" matches "pods/exec", "pods/*", or "*"
└── ResourceName matches (if rule.resourceNames is set and request specifies a name)
```

**Wildcard handling**:
- `*` in verbs matches any verb
- `*` in apiGroups matches any API group
- `*` in resources matches any resource
- `pods/*` matches any subresource of pods

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
