package output

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/hardik/kubectl-rbac-why/pkg/rbac"
)

func riskCategories(risks []rbac.RiskyPermission) map[string]bool {
	got := make(map[string]bool)
	for _, r := range risks {
		got[r.Category] = true
	}
	return got
}

func grantWithRule(rule rbacv1.PolicyRule) rbac.PermissionGrant {
	return rbac.PermissionGrant{
		Binding:      rbac.BindingInfo{Kind: "RoleBinding", Name: "b"},
		Role:         rbac.RoleInfo{Kind: "Role", Name: "r"},
		MatchingRule: rule,
		Scope:        rbac.ScopeNamespace,
	}
}

func TestAnalyzeRiskyPermissions(t *testing.T) {
	tests := []struct {
		name       string
		rule       rbacv1.PolicyRule
		want       []string // categories that must be present
		mustAbsent []string // categories that must NOT be present
	}{
		{
			name: "get deployments is not risky",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"get"},
				APIGroups: []string{"apps"},
				Resources: []string{"deployments"},
			},
			mustAbsent: []string{"secrets-access", "nodes-proxy", "cluster-admin"},
		},
		{
			name: "wildcard verbs on pods only is not cluster-admin",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"*"},
				APIGroups: []string{""},
				Resources: []string{"pods"},
			},
			want:       []string{"pod-create"},
			mustAbsent: []string{"cluster-admin", "secrets-access"},
		},
		{
			name: "get secrets is secrets-access",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"get"},
				APIGroups: []string{""},
				Resources: []string{"secrets"},
			},
			want: []string{"secrets-access"},
		},
		{
			name: "full wildcard rule is cluster-admin",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"*"},
				APIGroups: []string{"*"},
				Resources: []string{"*"},
			},
			want: []string{"cluster-admin", "secrets-access", "pod-exec"},
		},
		{
			name: "star-slash exec rule is pod-exec",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"create"},
				APIGroups: []string{""},
				Resources: []string{"*/exec"},
			},
			want: []string{"pod-exec"},
		},
		{
			name: "escalate verb on clusterroles is role-escalation",
			rule: rbacv1.PolicyRule{
				Verbs:     []string{"escalate"},
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"clusterroles"},
			},
			want:       []string{"role-escalation"},
			mustAbsent: []string{"binding-escalation"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			risks := AnalyzeRiskyPermissions([]rbac.PermissionGrant{grantWithRule(tt.rule)})
			got := riskCategories(risks)
			for _, w := range tt.want {
				if !got[w] {
					t.Errorf("expected category %q, got %v", w, got)
				}
			}
			for _, a := range tt.mustAbsent {
				if got[a] {
					t.Errorf("category %q must not match, got %v", a, got)
				}
			}
		})
	}
}

func TestPrintRiskyPermissions_IncompleteAnalysis(t *testing.T) {
	var buf bytes.Buffer
	PrintRiskyPermissions(&buf, nil, []error{errors.New("failed to get cluster role x")})
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
	PrintRiskyPermissions(&buf, nil, nil)
	if got := buf.String(); !strings.Contains(got, "No risky permissions detected.") {
		t.Errorf("expected clean message, got:\n%s", got)
	}
}
