package rbac

import (
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
)

func TestRuleMatches(t *testing.T) {
	tests := []struct {
		name     string
		rule     rbacv1.PolicyRule
		request  PermissionRequest
		expected bool
	}{
		{
			name: "exact match",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"get"},
				APIGroups: []string{""},
				Resources: []string{"pods"},
			},
			request:  PermissionRequest{Verb: "get", APIGroup: "", Resource: "pods"},
			expected: true,
		},
		{
			name: "wildcard verb",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"*"},
				APIGroups: []string{""},
				Resources: []string{"pods"},
			},
			request:  PermissionRequest{Verb: "delete", APIGroup: "", Resource: "pods"},
			expected: true,
		},
		{
			name: "wildcard api group",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"get"},
				APIGroups: []string{"*"},
				Resources: []string{"deployments"},
			},
			request:  PermissionRequest{Verb: "get", APIGroup: "apps", Resource: "deployments"},
			expected: true,
		},
		{
			name: "wildcard resource",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"get"},
				APIGroups: []string{""},
				Resources: []string{"*"},
			},
			request:  PermissionRequest{Verb: "get", APIGroup: "", Resource: "secrets"},
			expected: true,
		},
		{
			name: "subresource exact match",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"create"},
				APIGroups: []string{""},
				Resources: []string{"pods/exec"},
			},
			request:  PermissionRequest{Verb: "create", APIGroup: "", Resource: "pods", Subresource: "exec"},
			expected: true,
		},
		{
			// "<resource>/*" is not a valid upstream RBAC pattern; it must not
			// appear to grant a subresource the live cluster would deny.
			name: "resource/* does not grant a subresource (pods/* !-> pods/log)",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"get"},
				APIGroups: []string{""},
				Resources: []string{"pods/*"},
			},
			request:  PermissionRequest{Verb: "get", APIGroup: "", Resource: "pods", Subresource: "log"},
			expected: false,
		},
		{
			// "*/<subresource>" matches the subresource across all resources.
			name: "*/scale matches deployments/scale",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"update"},
				APIGroups: []string{"apps"},
				Resources: []string{"*/scale"},
			},
			request:  PermissionRequest{Verb: "update", APIGroup: "apps", Resource: "deployments", Subresource: "scale"},
			expected: true,
		},
		{
			name: "*/scale does not match a base-resource request",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"get"},
				APIGroups: []string{""},
				Resources: []string{"*/scale"},
			},
			request:  PermissionRequest{Verb: "get", APIGroup: "", Resource: "pods"},
			expected: false,
		},
		{
			name: "base-resource rule does not grant a subresource request",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"create"},
				APIGroups: []string{""},
				Resources: []string{"pods"},
			},
			request:  PermissionRequest{Verb: "create", APIGroup: "", Resource: "pods", Subresource: "exec"},
			expected: false,
		},
		{
			name: "resource name match",
			rule: rbacv1.PolicyRule{
				Verbs:         []string{"get"},
				APIGroups:     []string{""},
				Resources:     []string{"secrets"},
				ResourceNames: []string{"my-secret"},
			},
			request:  PermissionRequest{Verb: "get", APIGroup: "", Resource: "secrets", ResourceName: "my-secret"},
			expected: true,
		},
		{
			name: "resource name no match",
			rule: rbacv1.PolicyRule{
				Verbs:         []string{"get"},
				APIGroups:     []string{""},
				Resources:     []string{"secrets"},
				ResourceNames: []string{"my-secret"},
			},
			request:  PermissionRequest{Verb: "get", APIGroup: "", Resource: "secrets", ResourceName: "other-secret"},
			expected: false,
		},
		{
			name: "no match - different verb",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"get"},
				APIGroups: []string{""},
				Resources: []string{"pods"},
			},
			request:  PermissionRequest{Verb: "delete", APIGroup: "", Resource: "pods"},
			expected: false,
		},
		{
			name: "no match - different resource",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"get"},
				APIGroups: []string{""},
				Resources: []string{"pods"},
			},
			request:  PermissionRequest{Verb: "get", APIGroup: "", Resource: "secrets"},
			expected: false,
		},
		{
			name: "no match - different api group",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"get"},
				APIGroups: []string{"apps"},
				Resources: []string{"deployments"},
			},
			request:  PermissionRequest{Verb: "get", APIGroup: "extensions", Resource: "deployments"},
			expected: false,
		},
		{
			name: "multiple verbs - match",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"get", "list", "watch"},
				APIGroups: []string{""},
				Resources: []string{"pods"},
			},
			request:  PermissionRequest{Verb: "list", APIGroup: "", Resource: "pods"},
			expected: true,
		},
		{
			name: "multiple resources - match",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"get"},
				APIGroups: []string{""},
				Resources: []string{"pods", "services", "secrets"},
			},
			request:  PermissionRequest{Verb: "get", APIGroup: "", Resource: "services"},
			expected: true,
		},
		{
			name: "core api group empty string",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"get"},
				APIGroups: []string{""},
				Resources: []string{"pods"},
			},
			request:  PermissionRequest{Verb: "get", APIGroup: "", Resource: "pods"},
			expected: true,
		},
		{
			// Documented "could match" behavior: a name-scoped rule still
			// matches a can-i check that omits a specific resource name.
			name: "name-scoped rule could match when request omits a name",
			rule: rbacv1.PolicyRule{
				Verbs:         []string{"get"},
				APIGroups:     []string{""},
				Resources:     []string{"secrets"},
				ResourceNames: []string{"my-secret"},
			},
			request:  PermissionRequest{Verb: "get", APIGroup: "", Resource: "secrets"},
			expected: true,
		},
		{
			name: "non-resource URL exact match",
			rule: rbacv1.PolicyRule{
				Verbs:           []string{"get"},
				NonResourceURLs: []string{"/healthz"},
			},
			request:  PermissionRequest{Verb: "get", NonResourceURL: "/healthz"},
			expected: true,
		},
		{
			name: "non-resource URL prefix wildcard match",
			rule: rbacv1.PolicyRule{
				Verbs:           []string{"get"},
				NonResourceURLs: []string{"/api/*"},
			},
			request:  PermissionRequest{Verb: "get", NonResourceURL: "/api/v1"},
			expected: true,
		},
		{
			name: "non-resource URL wildcard matches any path",
			rule: rbacv1.PolicyRule{
				Verbs:           []string{"get"},
				NonResourceURLs: []string{"*"},
			},
			request:  PermissionRequest{Verb: "get", NonResourceURL: "/metrics"},
			expected: true,
		},
		{
			name: "non-resource URL no match - different path",
			rule: rbacv1.PolicyRule{
				Verbs:           []string{"get"},
				NonResourceURLs: []string{"/healthz"},
			},
			request:  PermissionRequest{Verb: "get", NonResourceURL: "/metrics"},
			expected: false,
		},
		{
			name: "non-resource URL no match - wrong verb",
			rule: rbacv1.PolicyRule{
				Verbs:           []string{"post"},
				NonResourceURLs: []string{"/healthz"},
			},
			request:  PermissionRequest{Verb: "get", NonResourceURL: "/healthz"},
			expected: false,
		},
		{
			// A wildcard resource rule does not imply non-resource URL access.
			name: "wildcard resource rule does not grant a non-resource URL",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"get"},
				APIGroups: []string{"*"},
				Resources: []string{"*"},
			},
			request:  PermissionRequest{Verb: "get", NonResourceURL: "/healthz"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RuleMatches(tt.rule, tt.request)
			if result != tt.expected {
				t.Errorf("RuleMatches() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestSubjectMatches(t *testing.T) {
	tests := []struct {
		name           string
		bindingSubject rbacv1.Subject
		requestSubject Subject
		expected       bool
	}{
		{
			name: "service account match",
			bindingSubject: rbacv1.Subject{
				Kind:      "ServiceAccount",
				Name:      "my-sa",
				Namespace: "default",
			},
			requestSubject: Subject{
				Kind:      "ServiceAccount",
				Name:      "my-sa",
				Namespace: "default",
			},
			expected: true,
		},
		{
			name: "service account different namespace",
			bindingSubject: rbacv1.Subject{
				Kind:      "ServiceAccount",
				Name:      "my-sa",
				Namespace: "default",
			},
			requestSubject: Subject{
				Kind:      "ServiceAccount",
				Name:      "my-sa",
				Namespace: "kube-system",
			},
			expected: false,
		},
		{
			name: "user match",
			bindingSubject: rbacv1.Subject{
				Kind: "User",
				Name: "jane",
			},
			requestSubject: Subject{
				Kind: "User",
				Name: "jane",
			},
			expected: true,
		},
		{
			name: "group match",
			bindingSubject: rbacv1.Subject{
				Kind: "Group",
				Name: "developers",
			},
			requestSubject: Subject{
				Kind: "Group",
				Name: "developers",
			},
			expected: true,
		},
		{
			name: "different kind",
			bindingSubject: rbacv1.Subject{
				Kind: "User",
				Name: "my-sa",
			},
			requestSubject: Subject{
				Kind: "ServiceAccount",
				Name: "my-sa",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SubjectMatches(tt.bindingSubject, tt.requestSubject)
			if result != tt.expected {
				t.Errorf("SubjectMatches() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestSubjectMatchesWithGroups(t *testing.T) {
	tests := []struct {
		name           string
		bindingSubject rbacv1.Subject
		requestSubject Subject
		groups         []string
		expected       bool
	}{
		{
			name: "direct match",
			bindingSubject: rbacv1.Subject{
				Kind:      "ServiceAccount",
				Name:      "my-sa",
				Namespace: "default",
			},
			requestSubject: Subject{
				Kind:      "ServiceAccount",
				Name:      "my-sa",
				Namespace: "default",
			},
			groups:   []string{"system:authenticated"},
			expected: true,
		},
		{
			name: "group match - system:authenticated",
			bindingSubject: rbacv1.Subject{
				Kind: "Group",
				Name: "system:authenticated",
			},
			requestSubject: Subject{
				Kind:      "ServiceAccount",
				Name:      "my-sa",
				Namespace: "default",
			},
			groups:   []string{"system:authenticated", "system:serviceaccounts"},
			expected: true,
		},
		{
			name: "group match - system:serviceaccounts",
			bindingSubject: rbacv1.Subject{
				Kind: "Group",
				Name: "system:serviceaccounts",
			},
			requestSubject: Subject{
				Kind:      "ServiceAccount",
				Name:      "my-sa",
				Namespace: "default",
			},
			groups:   []string{"system:authenticated", "system:serviceaccounts"},
			expected: true,
		},
		{
			name: "group match - namespace specific",
			bindingSubject: rbacv1.Subject{
				Kind: "Group",
				Name: "system:serviceaccounts:default",
			},
			requestSubject: Subject{
				Kind:      "ServiceAccount",
				Name:      "my-sa",
				Namespace: "default",
			},
			groups:   []string{"system:authenticated", "system:serviceaccounts", "system:serviceaccounts:default"},
			expected: true,
		},
		{
			name: "no match - different namespace group",
			bindingSubject: rbacv1.Subject{
				Kind: "Group",
				Name: "system:serviceaccounts:kube-system",
			},
			requestSubject: Subject{
				Kind:      "ServiceAccount",
				Name:      "my-sa",
				Namespace: "default",
			},
			groups:   []string{"system:authenticated", "system:serviceaccounts", "system:serviceaccounts:default"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SubjectMatchesWithGroups(tt.bindingSubject, tt.requestSubject, tt.groups)
			if result != tt.expected {
				t.Errorf("SubjectMatchesWithGroups() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestGetImplicitGroups(t *testing.T) {
	tests := []struct {
		name           string
		subject        Subject
		expectedGroups []string
	}{
		{
			name: "service account",
			subject: Subject{
				Kind:      "ServiceAccount",
				Name:      "my-sa",
				Namespace: "default",
			},
			expectedGroups: []string{
				"system:authenticated",
				"system:serviceaccounts",
				"system:serviceaccounts:default",
			},
		},
		{
			name: "user",
			subject: Subject{
				Kind: "User",
				Name: "jane",
			},
			expectedGroups: []string{
				"system:authenticated",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetImplicitGroups(tt.subject)
			if len(result) != len(tt.expectedGroups) {
				t.Errorf("GetImplicitGroups() returned %d groups, expected %d", len(result), len(tt.expectedGroups))
				return
			}
			for i, g := range tt.expectedGroups {
				if result[i] != g {
					t.Errorf("GetImplicitGroups()[%d] = %s, expected %s", i, result[i], g)
				}
			}
		})
	}
}
