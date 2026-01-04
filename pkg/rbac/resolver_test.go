package rbac

import (
	"context"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/hardik/kubectl-rbac-why/pkg/client"
)

func TestParseSubject(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    Subject
		expectError bool
	}{
		{
			name:  "service account",
			input: "system:serviceaccount:default:my-sa",
			expected: Subject{
				Kind:      "ServiceAccount",
				Namespace: "default",
				Name:      "my-sa",
			},
		},
		{
			name:  "service account in kube-system",
			input: "system:serviceaccount:kube-system:coredns",
			expected: Subject{
				Kind:      "ServiceAccount",
				Namespace: "kube-system",
				Name:      "coredns",
			},
		},
		{
			name:  "system group",
			input: "system:masters",
			expected: Subject{
				Kind: "Group",
				Name: "system:masters",
			},
		},
		{
			name:  "user",
			input: "jane",
			expected: Subject{
				Kind: "User",
				Name: "jane",
			},
		},
		{
			name:  "user with email",
			input: "jane@example.com",
			expected: Subject{
				Kind: "User",
				Name: "jane@example.com",
			},
		},
		{
			name:        "empty string",
			input:       "",
			expectError: true,
		},
		{
			name:        "invalid service account format",
			input:       "system:serviceaccount:default",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseSubject(tt.input)
			if tt.expectError {
				if err == nil {
					t.Errorf("ParseSubject() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("ParseSubject() unexpected error: %v", err)
				return
			}
			if result.Kind != tt.expected.Kind {
				t.Errorf("ParseSubject().Kind = %s, expected %s", result.Kind, tt.expected.Kind)
			}
			if result.Name != tt.expected.Name {
				t.Errorf("ParseSubject().Name = %s, expected %s", result.Name, tt.expected.Name)
			}
			if result.Namespace != tt.expected.Namespace {
				t.Errorf("ParseSubject().Namespace = %s, expected %s", result.Namespace, tt.expected.Namespace)
			}
		})
	}
}

func TestResolvePermission_RoleBinding(t *testing.T) {
	mockClient := client.NewMockRBACClient()

	// Add a Role
	mockClient.AddRole(rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod-reader",
			Namespace: "default",
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:     []string{"get", "list", "watch"},
				APIGroups: []string{""},
				Resources: []string{"pods"},
			},
		},
	})

	// Add a RoleBinding
	mockClient.AddRoleBinding(rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "read-pods",
			Namespace: "default",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "test-sa",
				Namespace: "default",
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind: "Role",
			Name: "pod-reader",
		},
	})

	resolver := NewResolver(mockClient)

	result, err := resolver.ResolvePermission(
		context.Background(),
		Subject{Kind: "ServiceAccount", Name: "test-sa", Namespace: "default"},
		PermissionRequest{Verb: "get", APIGroup: "", Resource: "pods", Namespace: "default"},
	)

	if err != nil {
		t.Fatalf("ResolvePermission() error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("ResolvePermission().Allowed = false, expected true")
	}

	if len(result.Grants) != 1 {
		t.Fatalf("ResolvePermission() returned %d grants, expected 1", len(result.Grants))
	}

	grant := result.Grants[0]
	if grant.Binding.Kind != "RoleBinding" {
		t.Errorf("Grant.Binding.Kind = %s, expected RoleBinding", grant.Binding.Kind)
	}
	if grant.Binding.Name != "read-pods" {
		t.Errorf("Grant.Binding.Name = %s, expected read-pods", grant.Binding.Name)
	}
	if grant.Role.Kind != "Role" {
		t.Errorf("Grant.Role.Kind = %s, expected Role", grant.Role.Kind)
	}
	if grant.Role.Name != "pod-reader" {
		t.Errorf("Grant.Role.Name = %s, expected pod-reader", grant.Role.Name)
	}
}

func TestResolvePermission_ClusterRoleBinding(t *testing.T) {
	mockClient := client.NewMockRBACClient()

	// Add a ClusterRole
	mockClient.AddClusterRole(rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "secret-reader",
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:     []string{"get", "list"},
				APIGroups: []string{""},
				Resources: []string{"secrets"},
			},
		},
	})

	// Add a ClusterRoleBinding
	mockClient.AddClusterRoleBinding(rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "read-secrets-global",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "admin-sa",
				Namespace: "kube-system",
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind: "ClusterRole",
			Name: "secret-reader",
		},
	})

	resolver := NewResolver(mockClient)

	result, err := resolver.ResolvePermission(
		context.Background(),
		Subject{Kind: "ServiceAccount", Name: "admin-sa", Namespace: "kube-system"},
		PermissionRequest{Verb: "get", APIGroup: "", Resource: "secrets", Namespace: "default"},
	)

	if err != nil {
		t.Fatalf("ResolvePermission() error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("ResolvePermission().Allowed = false, expected true")
	}

	if len(result.Grants) != 1 {
		t.Fatalf("ResolvePermission() returned %d grants, expected 1", len(result.Grants))
	}

	grant := result.Grants[0]
	if grant.Binding.Kind != "ClusterRoleBinding" {
		t.Errorf("Grant.Binding.Kind = %s, expected ClusterRoleBinding", grant.Binding.Kind)
	}
	if grant.Scope != ScopeClusterWide {
		t.Errorf("Grant.Scope = %s, expected cluster-wide", grant.Scope)
	}
}

func TestResolvePermission_GroupBinding(t *testing.T) {
	mockClient := client.NewMockRBACClient()

	// Add a ClusterRole
	mockClient.AddClusterRole(rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-reader",
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:     []string{"get", "list"},
				APIGroups: []string{""},
				Resources: []string{"nodes"},
			},
		},
	})

	// Add a ClusterRoleBinding to system:serviceaccounts group
	mockClient.AddClusterRoleBinding(rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "all-sa-read-nodes",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind: "Group",
				Name: "system:serviceaccounts",
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind: "ClusterRole",
			Name: "node-reader",
		},
	})

	resolver := NewResolver(mockClient)

	// Any service account should match via the group
	result, err := resolver.ResolvePermission(
		context.Background(),
		Subject{Kind: "ServiceAccount", Name: "any-sa", Namespace: "any-ns"},
		PermissionRequest{Verb: "list", APIGroup: "", Resource: "nodes"},
	)

	if err != nil {
		t.Fatalf("ResolvePermission() error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("ResolvePermission().Allowed = false, expected true")
	}

	if len(result.Grants) != 1 {
		t.Fatalf("ResolvePermission() returned %d grants, expected 1", len(result.Grants))
	}
}

func TestResolvePermission_Denied(t *testing.T) {
	mockClient := client.NewMockRBACClient()

	// Add a Role for different SA
	mockClient.AddRole(rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "secret-reader",
			Namespace: "default",
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:     []string{"get"},
				APIGroups: []string{""},
				Resources: []string{"secrets"},
			},
		},
	})

	mockClient.AddRoleBinding(rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "read-secrets",
			Namespace: "default",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "allowed-sa",
				Namespace: "default",
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind: "Role",
			Name: "secret-reader",
		},
	})

	resolver := NewResolver(mockClient)

	// Different SA should be denied
	result, err := resolver.ResolvePermission(
		context.Background(),
		Subject{Kind: "ServiceAccount", Name: "denied-sa", Namespace: "default"},
		PermissionRequest{Verb: "get", APIGroup: "", Resource: "secrets", Namespace: "default"},
	)

	if err != nil {
		t.Fatalf("ResolvePermission() error: %v", err)
	}

	if result.Allowed {
		t.Errorf("ResolvePermission().Allowed = true, expected false")
	}

	if len(result.Grants) != 0 {
		t.Errorf("ResolvePermission() returned %d grants, expected 0", len(result.Grants))
	}
}

func TestResolvePermission_MultipleGrants(t *testing.T) {
	mockClient := client.NewMockRBACClient()

	// Add a Role
	mockClient.AddRole(rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod-reader",
			Namespace: "default",
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:     []string{"get", "list"},
				APIGroups: []string{""},
				Resources: []string{"pods"},
			},
		},
	})

	// Add a ClusterRole
	mockClient.AddClusterRole(rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "global-pod-reader",
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:     []string{"get", "list", "watch"},
				APIGroups: []string{""},
				Resources: []string{"pods"},
			},
		},
	})

	// Add both bindings
	mockClient.AddRoleBinding(rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "read-pods-ns",
			Namespace: "default",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "test-sa",
				Namespace: "default",
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind: "Role",
			Name: "pod-reader",
		},
	})

	mockClient.AddClusterRoleBinding(rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "read-pods-global",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "test-sa",
				Namespace: "default",
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind: "ClusterRole",
			Name: "global-pod-reader",
		},
	})

	resolver := NewResolver(mockClient)

	result, err := resolver.ResolvePermission(
		context.Background(),
		Subject{Kind: "ServiceAccount", Name: "test-sa", Namespace: "default"},
		PermissionRequest{Verb: "get", APIGroup: "", Resource: "pods", Namespace: "default"},
	)

	if err != nil {
		t.Fatalf("ResolvePermission() error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("ResolvePermission().Allowed = false, expected true")
	}

	// Should have 2 grants (one from RoleBinding, one from ClusterRoleBinding)
	if len(result.Grants) != 2 {
		t.Errorf("ResolvePermission() returned %d grants, expected 2", len(result.Grants))
	}
}

func TestResolvePermission_RoleBindingToClusterRole(t *testing.T) {
	mockClient := client.NewMockRBACClient()

	// Add a ClusterRole
	mockClient.AddClusterRole(rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "edit",
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:     []string{"*"},
				APIGroups: []string{""},
				Resources: []string{"pods", "services", "configmaps"},
			},
		},
	})

	// RoleBinding that references ClusterRole (common pattern)
	mockClient.AddRoleBinding(rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "edit-in-ns",
			Namespace: "default",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "editor-sa",
				Namespace: "default",
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind: "ClusterRole",
			Name: "edit",
		},
	})

	resolver := NewResolver(mockClient)

	result, err := resolver.ResolvePermission(
		context.Background(),
		Subject{Kind: "ServiceAccount", Name: "editor-sa", Namespace: "default"},
		PermissionRequest{Verb: "delete", APIGroup: "", Resource: "pods", Namespace: "default"},
	)

	if err != nil {
		t.Fatalf("ResolvePermission() error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("ResolvePermission().Allowed = false, expected true")
	}

	if len(result.Grants) != 1 {
		t.Fatalf("ResolvePermission() returned %d grants, expected 1", len(result.Grants))
	}

	grant := result.Grants[0]
	if grant.Binding.Kind != "RoleBinding" {
		t.Errorf("Grant.Binding.Kind = %s, expected RoleBinding", grant.Binding.Kind)
	}
	if grant.Role.Kind != "ClusterRole" {
		t.Errorf("Grant.Role.Kind = %s, expected ClusterRole", grant.Role.Kind)
	}
	if grant.Scope != ScopeNamespace {
		t.Errorf("Grant.Scope = %s, expected namespace", grant.Scope)
	}
}
