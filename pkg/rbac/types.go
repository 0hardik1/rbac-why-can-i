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
}

// FullResource returns the resource with subresource if present (e.g., "pods/exec")
func (p PermissionRequest) FullResource() string {
	if p.Subresource != "" {
		return p.Resource + "/" + p.Subresource
	}
	return p.Resource
}

// Subject represents who is requesting access
type Subject struct {
	Kind      string   // User, Group, ServiceAccount
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

// RiskyPermission identifies a potentially dangerous permission
type RiskyPermission struct {
	Category    string // e.g., "secrets", "privilege-escalation", "node-access"
	Description string
	Severity    string // "critical", "high", "medium"
	Grants      []PermissionGrant
}
