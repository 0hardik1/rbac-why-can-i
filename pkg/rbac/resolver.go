package rbac

import (
	"context"
	"fmt"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/hardik/kubectl-rbac-why/pkg/client"
)

// Resolver handles RBAC permission resolution
type Resolver struct {
	client client.RBACClient
}

// NewResolver creates a new RBAC resolver
func NewResolver(c client.RBACClient) *Resolver {
	return &Resolver{client: c}
}

// ParseSubject parses a --as string into a Subject
func ParseSubject(asString string) (Subject, error) {
	if asString == "" {
		return Subject{}, fmt.Errorf("subject cannot be empty")
	}

	// Format: "system:serviceaccount:namespace:name"
	if strings.HasPrefix(asString, "system:serviceaccount:") {
		parts := strings.Split(asString, ":")
		if len(parts) != 4 {
			return Subject{}, fmt.Errorf("invalid serviceaccount format: %s (expected system:serviceaccount:namespace:name)", asString)
		}
		return Subject{
			Kind:      "ServiceAccount",
			Namespace: parts[2],
			Name:      parts[3],
		}, nil
	}

	// Groups typically start with "system:" but aren't serviceaccounts
	if strings.HasPrefix(asString, "system:") {
		return Subject{
			Kind: "Group",
			Name: asString,
		}, nil
	}

	// Otherwise treat as User
	return Subject{
		Kind: "User",
		Name: asString,
	}, nil
}

// ResolvePermission finds all grants for a permission request
func (r *Resolver) ResolvePermission(ctx context.Context, subject Subject, request PermissionRequest) (*PermissionResult, error) {
	result := &PermissionResult{
		Request: request,
		Subject: subject,
		Grants:  []PermissionGrant{},
	}

	// Get implicit groups for the subject
	groups := GetImplicitGroups(subject)

	// Find all ClusterRoleBindings that reference this subject
	crbs, err := r.client.ListClusterRoleBindings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster role bindings: %w", err)
	}

	for _, crb := range crbs.Items {
		if !r.bindingMatchesSubject(crb.Subjects, subject, groups) {
			continue
		}

		// Get the referenced ClusterRole
		clusterRole, err := r.client.GetClusterRole(ctx, crb.RoleRef.Name)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("failed to get cluster role %s: %w", crb.RoleRef.Name, err))
			continue
		}

		// Check each rule in the role
		for _, rule := range clusterRole.Rules {
			if RuleMatches(rule, request) {
				grant := PermissionGrant{
					Binding: BindingInfo{
						Kind: "ClusterRoleBinding",
						Name: crb.Name,
					},
					Role: RoleInfo{
						Kind: "ClusterRole",
						Name: clusterRole.Name,
					},
					MatchingRule: rule,
					Scope:        ScopeClusterWide,
				}
				result.Grants = append(result.Grants, grant)
			}
		}
	}

	// If namespace is specified, also check RoleBindings in that namespace
	if request.Namespace != "" {
		rbs, err := r.client.ListRoleBindings(ctx, request.Namespace)
		if err != nil {
			return nil, fmt.Errorf("failed to list role bindings in namespace %s: %w", request.Namespace, err)
		}

		for _, rb := range rbs.Items {
			if !r.bindingMatchesSubject(rb.Subjects, subject, groups) {
				continue
			}

			var rules []rbacv1.PolicyRule
			var roleInfo RoleInfo

			// RoleBinding can reference either a Role or ClusterRole
			if rb.RoleRef.Kind == "ClusterRole" {
				clusterRole, err := r.client.GetClusterRole(ctx, rb.RoleRef.Name)
				if err != nil {
					result.Errors = append(result.Errors, fmt.Errorf("failed to get cluster role %s: %w", rb.RoleRef.Name, err))
					continue
				}
				rules = clusterRole.Rules
				roleInfo = RoleInfo{
					Kind: "ClusterRole",
					Name: clusterRole.Name,
				}
			} else {
				role, err := r.client.GetRole(ctx, request.Namespace, rb.RoleRef.Name)
				if err != nil {
					result.Errors = append(result.Errors, fmt.Errorf("failed to get role %s in namespace %s: %w", rb.RoleRef.Name, request.Namespace, err))
					continue
				}
				rules = role.Rules
				roleInfo = RoleInfo{
					Kind:      "Role",
					Name:      role.Name,
					Namespace: role.Namespace,
				}
			}

			// Check each rule
			for _, rule := range rules {
				if RuleMatches(rule, request) {
					grant := PermissionGrant{
						Binding: BindingInfo{
							Kind:      "RoleBinding",
							Name:      rb.Name,
							Namespace: rb.Namespace,
						},
						Role:         roleInfo,
						MatchingRule: rule,
						Scope:        ScopeNamespace,
					}
					result.Grants = append(result.Grants, grant)
				}
			}
		}
	}

	result.Allowed = len(result.Grants) > 0
	return result, nil
}

// bindingMatchesSubject checks if any subject in the binding matches the request subject
func (r *Resolver) bindingMatchesSubject(subjects []rbacv1.Subject, subject Subject, groups []string) bool {
	for _, s := range subjects {
		if SubjectMatchesWithGroups(s, subject, groups) {
			return true
		}
	}
	return false
}

// ResolveAllPermissions gets all permissions for a subject (for risky permission analysis)
func (r *Resolver) ResolveAllPermissions(ctx context.Context, subject Subject, namespace string) ([]PermissionGrant, error) {
	var grants []PermissionGrant
	groups := GetImplicitGroups(subject)

	// Get all ClusterRoleBindings
	crbs, err := r.client.ListClusterRoleBindings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster role bindings: %w", err)
	}

	for _, crb := range crbs.Items {
		if !r.bindingMatchesSubject(crb.Subjects, subject, groups) {
			continue
		}

		clusterRole, err := r.client.GetClusterRole(ctx, crb.RoleRef.Name)
		if err != nil {
			continue
		}

		for _, rule := range clusterRole.Rules {
			grant := PermissionGrant{
				Binding: BindingInfo{
					Kind: "ClusterRoleBinding",
					Name: crb.Name,
				},
				Role: RoleInfo{
					Kind: "ClusterRole",
					Name: clusterRole.Name,
				},
				MatchingRule: rule,
				Scope:        ScopeClusterWide,
			}
			grants = append(grants, grant)
		}
	}

	// Get RoleBindings if namespace specified
	if namespace != "" {
		rbs, err := r.client.ListRoleBindings(ctx, namespace)
		if err != nil {
			return nil, fmt.Errorf("failed to list role bindings: %w", err)
		}

		for _, rb := range rbs.Items {
			if !r.bindingMatchesSubject(rb.Subjects, subject, groups) {
				continue
			}

			var rules []rbacv1.PolicyRule
			var roleInfo RoleInfo

			if rb.RoleRef.Kind == "ClusterRole" {
				clusterRole, err := r.client.GetClusterRole(ctx, rb.RoleRef.Name)
				if err != nil {
					continue
				}
				rules = clusterRole.Rules
				roleInfo = RoleInfo{Kind: "ClusterRole", Name: clusterRole.Name}
			} else {
				role, err := r.client.GetRole(ctx, namespace, rb.RoleRef.Name)
				if err != nil {
					continue
				}
				rules = role.Rules
				roleInfo = RoleInfo{Kind: "Role", Name: role.Name, Namespace: role.Namespace}
			}

			for _, rule := range rules {
				grant := PermissionGrant{
					Binding: BindingInfo{
						Kind:      "RoleBinding",
						Name:      rb.Name,
						Namespace: rb.Namespace,
					},
					Role:         roleInfo,
					MatchingRule: rule,
					Scope:        ScopeNamespace,
				}
				grants = append(grants, grant)
			}
		}
	}

	return grants, nil
}
