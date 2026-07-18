package rbac

import (
	rbacv1 "k8s.io/api/rbac/v1"
)

// PermissionRequest represents the permission being checked
type PermissionRequest struct {
	Verb         string
	APIGroup     string
	Resource     string
	Subresource  string
	ResourceName string
	Namespace    string // Empty for cluster-scoped resources

	// NonResourceURL is set instead of Resource/APIGroup for non-resource
	// requests such as "/healthz" or "/metrics". These are grantable only
	// via ClusterRoles (nonResourceURLs rules).
	NonResourceURL string
}

// FullResource returns the resource with subresource if present (e.g.,
// "pods/exec"), or the non-resource URL when the request targets one.
func (p PermissionRequest) FullResource() string {
	if p.NonResourceURL != "" {
		return p.NonResourceURL
	}
	if p.Subresource != "" {
		return p.Resource + "/" + p.Subresource
	}
	return p.Resource
}

// Subject represents who is requesting access
type Subject struct {
	Kind      string // User, Group, ServiceAccount
	Name      string
	Namespace string   // Only for ServiceAccount
	Groups    []string // Explicit groups (e.g., from client certificate)
}

// String returns a human-readable representation of the subject
func (s Subject) String() string {
	if s.Kind == "ServiceAccount" {
		return "ServiceAccount " + s.Namespace + "/" + s.Name
	}
	return s.Kind + " " + s.Name
}

// GrantScope indicates whether a grant is namespace-scoped or cluster-wide
type GrantScope string

const (
	ScopeNamespace   GrantScope = "namespace"
	ScopeClusterWide GrantScope = "cluster-wide"
)

// BindingInfo contains information about a RoleBinding or ClusterRoleBinding
type BindingInfo struct {
	Kind      string // RoleBinding or ClusterRoleBinding
	Name      string
	Namespace string // Empty for ClusterRoleBinding
}

// RoleInfo contains information about a Role or ClusterRole
type RoleInfo struct {
	Kind      string // Role or ClusterRole
	Name      string
	Namespace string // Empty for ClusterRole
}

// PermissionGrant represents a single path by which permission is granted
type PermissionGrant struct {
	// The binding that connects subject to role
	Binding BindingInfo
	// The role/clusterrole that contains the rule
	Role RoleInfo
	// The specific rule that grants the permission
	MatchingRule rbacv1.PolicyRule
	// Scope of the grant
	Scope GrantScope
}

// PermissionResult holds all grants for a permission check
type PermissionResult struct {
	Request PermissionRequest
	Subject Subject
	Allowed bool
	Grants  []PermissionGrant
	Errors  []error
}

// Incomplete reports whether some RBAC objects could not be read during
// resolution. When true, Grants may be missing paths and Allowed=false must
// not be presented as a definitive denial.
func (r *PermissionResult) Incomplete() bool {
	return len(r.Errors) > 0
}

// RiskyPermission identifies a potentially dangerous permission
type RiskyPermission struct {
	Category    string // e.g., "secrets", "privilege-escalation", "node-access"
	Description string
	Severity    string // "critical", "high", "medium"
	Grants      []PermissionGrant
}

// SubjectGrant is a subject that holds a permission, together with the binding
// and role chains that grant it. Produced by reverse lookup (who-can).
type SubjectGrant struct {
	Subject Subject
	Grants  []PermissionGrant
}

// ReverseResult holds every subject that can perform a permission request
// (the inverse of PermissionResult).
type ReverseResult struct {
	Request  PermissionRequest
	Subjects []SubjectGrant
}

// RuleGrant pairs a policy rule with the grant chains that provide it.
type RuleGrant struct {
	Rule   rbacv1.PolicyRule
	Grants []PermissionGrant
}

// PermissionComparison is the result of comparing two subjects' effective
// rules: the rules unique to each, and those they share.
type PermissionComparison struct {
	SubjectA   Subject
	SubjectB   Subject
	OnlyA      []RuleGrant // rules only SubjectA has
	OnlyB      []RuleGrant // rules only SubjectB has
	Shared     []RuleGrant // rules both have (grants shown from SubjectA)
	SoftErrors []error     // non-fatal errors from either resolution
}
