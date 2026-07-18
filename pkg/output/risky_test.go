package output

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/hardik/kubectl-rbac-why/pkg/rbac"
)

// findPattern returns the RiskyPattern with the given category, failing the
// test if it does not exist (so the tests stay honest if a category is renamed).
func findPattern(t *testing.T, category string) RiskyPattern {
	t.Helper()
	for _, p := range RiskyPatterns {
		if p.Category == category {
			return p
		}
	}
	t.Fatalf("no RiskyPattern with category %q", category)
	return RiskyPattern{}
}

func TestMatchesRiskyPattern(t *testing.T) {
	tests := []struct {
		name     string
		rule     rbacv1.PolicyRule
		category string
		want     bool
	}{
		{
			// Regression: before the fix, the pattern's "*" group/resource
			// entries made these checks vacuous, so any read verb tripped
			// secrets-access. A read on a non-core resource must not.
			name: "get deployments is NOT secrets-access (group must match)",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"get", "list", "watch"},
				APIGroups: []string{"apps"},
				Resources: []string{"deployments"},
			},
			category: "secrets-access",
			want:     false,
		},
		{
			// Regression exercising the resource clause: a core-group read of
			// a non-secret resource must not trip secrets-access.
			name: "get configmaps is NOT secrets-access (resource must match)",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"get"},
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
			},
			category: "secrets-access",
			want:     false,
		},
		{
			name: "get secrets IS secrets-access",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"get"},
				APIGroups: []string{""},
				Resources: []string{"secrets"},
			},
			category: "secrets-access",
			want:     true,
		},
		{
			name: "create pods/exec IS pod-exec",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"create"},
				APIGroups: []string{""},
				Resources: []string{"pods/exec"},
			},
			category: "pod-exec",
			want:     true,
		},
		{
			name: "star-slash exec rule IS pod-exec",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"create"},
				APIGroups: []string{""},
				Resources: []string{"*/exec"},
			},
			category: "pod-exec",
			want:     true,
		},
		{
			name: "create configmaps is NOT pod-exec",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"create"},
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
			},
			category: "pod-exec",
			want:     false,
		},
		{
			name: "wildcard rule IS cluster-admin",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"*"},
				APIGroups: []string{"*"},
				Resources: []string{"*"},
			},
			category: "cluster-admin",
			want:     true,
		},
		{
			name: "wildcard rule also trips secrets-access",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"*"},
				APIGroups: []string{"*"},
				Resources: []string{"*"},
			},
			category: "secrets-access",
			want:     true,
		},
		{
			name: "non-wildcard rule is NOT cluster-admin",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"get", "list"},
				APIGroups: []string{""},
				Resources: []string{"secrets"},
			},
			category: "cluster-admin",
			want:     false,
		},
		{
			// Wildcard verbs on a narrow resource are risky for that resource,
			// but not cluster-admin.
			name: "wildcard verbs on pods only is NOT cluster-admin",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"*"},
				APIGroups: []string{""},
				Resources: []string{"pods"},
			},
			category: "cluster-admin",
			want:     false,
		},
		{
			name: "escalate verb on clusterroles IS role-escalation",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"escalate"},
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"clusterroles"},
			},
			category: "role-escalation",
			want:     true,
		},
		{
			name: "bind verb on rolebindings IS binding-escalation",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"bind"},
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"rolebindings"},
			},
			category: "binding-escalation",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesRiskyPattern(tt.rule, findPattern(t, tt.category))
			if got != tt.want {
				t.Errorf("matchesRiskyPattern(%s) = %v, want %v", tt.category, got, tt.want)
			}
		})
	}
}

// grantWith builds a PermissionGrant carrying the given rule.
func grantWith(rule rbacv1.PolicyRule) rbac.PermissionGrant {
	return rbac.PermissionGrant{
		Binding:      rbac.BindingInfo{Kind: "ClusterRoleBinding", Name: "b"},
		Role:         rbac.RoleInfo{Kind: "ClusterRole", Name: "r"},
		MatchingRule: rule,
		Scope:        rbac.ScopeClusterWide,
	}
}

func categorySet(risks []rbac.RiskyPermission) map[string]bool {
	m := make(map[string]bool, len(risks))
	for _, r := range risks {
		m[r.Category] = true
	}
	return m
}

func TestAnalyzeRiskyPermissions(t *testing.T) {
	t.Run("benign read produces no risks", func(t *testing.T) {
		grants := []rbac.PermissionGrant{
			grantWith(rbacv1.PolicyRule{
				Verbs:     []string{"get", "list", "watch"},
				APIGroups: []string{"apps"},
				Resources: []string{"deployments"},
			}),
		}
		risks := AnalyzeRiskyPermissions(grants)
		if len(risks) != 0 {
			t.Errorf("expected no risks for read-only deployments access, got %v", categorySet(risks))
		}
	})

	t.Run("secrets read flags only secrets-access", func(t *testing.T) {
		grants := []rbac.PermissionGrant{
			grantWith(rbacv1.PolicyRule{
				Verbs:     []string{"get", "list"},
				APIGroups: []string{""},
				Resources: []string{"secrets"},
			}),
		}
		cats := categorySet(AnalyzeRiskyPermissions(grants))
		if !cats["secrets-access"] {
			t.Errorf("expected secrets-access, got %v", cats)
		}
		if cats["pod-exec"] || cats["cluster-admin"] || cats["impersonate"] {
			t.Errorf("secrets read should not trip exec/admin/impersonate, got %v", cats)
		}
	})

	t.Run("wildcard grant trips cluster-admin", func(t *testing.T) {
		grants := []rbac.PermissionGrant{
			grantWith(rbacv1.PolicyRule{
				Verbs:     []string{"*"},
				APIGroups: []string{"*"},
				Resources: []string{"*"},
			}),
		}
		cats := categorySet(AnalyzeRiskyPermissions(grants))
		if !cats["cluster-admin"] {
			t.Errorf("expected cluster-admin for wildcard grant, got %v", cats)
		}
	})

	t.Run("wildcard verbs on pods trips pod-create but not cluster-admin", func(t *testing.T) {
		grants := []rbac.PermissionGrant{
			grantWith(rbacv1.PolicyRule{
				Verbs:     []string{"*"},
				APIGroups: []string{""},
				Resources: []string{"pods"},
			}),
		}
		cats := categorySet(AnalyzeRiskyPermissions(grants))
		if !cats["pod-create"] {
			t.Errorf("expected pod-create, got %v", cats)
		}
		if cats["cluster-admin"] || cats["secrets-access"] {
			t.Errorf("narrow wildcard-verb rule must not trip cluster-admin/secrets, got %v", cats)
		}
	})
}

func TestPrintRiskyPermissions_IncompleteAnalysis(t *testing.T) {
	var buf bytes.Buffer
	PrintRiskyPermissions(&buf, nil, []error{errors.New("failed to get cluster role x")}, false)
	got := buf.String()
	if !strings.Contains(got, "INCOMPLETE") {
		t.Errorf("expected INCOMPLETE warning, got:\n%s", got)
	}
	if !strings.Contains(got, "result incomplete") {
		t.Errorf("expected incomplete qualifier on the no-risks line, got:\n%s", got)
	}
	if strings.Contains(got, "No risky permissions detected.") {
		t.Errorf("must not print a clean bill of health when incomplete, got:\n%s", got)
	}
}

func TestPrintRiskyPermissions_CleanWhenComplete(t *testing.T) {
	var buf bytes.Buffer
	PrintRiskyPermissions(&buf, nil, nil, false)
	if got := buf.String(); !strings.Contains(got, "No risky permissions detected.") {
		t.Errorf("expected clean message, got:\n%s", got)
	}
}
