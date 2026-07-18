package output

import (
	"bytes"
	"encoding/json"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/hardik/kubectl-rbac-why/pkg/rbac"
)

func TestJSONPrinter(t *testing.T) {
	result := &rbac.PermissionResult{
		Allowed: true,
		Subject: rbac.Subject{Kind: "ServiceAccount", Name: "app", Namespace: "default"},
		Request: rbac.PermissionRequest{Verb: "get", APIGroup: "", Resource: "secrets", Namespace: "default"},
		Grants: []rbac.PermissionGrant{{
			Binding:      rbac.BindingInfo{Kind: "RoleBinding", Name: "rb", Namespace: "default"},
			Role:         rbac.RoleInfo{Kind: "Role", Name: "secret-reader", Namespace: "default"},
			MatchingRule: rbacv1.PolicyRule{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"secrets"}},
			Scope:        rbac.ScopeNamespace,
		}},
	}

	var buf bytes.Buffer
	if err := (&JSONPrinter{}).Print(&buf, result, nil); err != nil {
		t.Fatalf("Print error: %v", err)
	}

	var out JSONOutput
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if !out.Allowed {
		t.Error("expected allowed=true")
	}
	if out.Subject.Kind != "ServiceAccount" || out.Subject.Name != "app" {
		t.Errorf("subject = %+v", out.Subject)
	}
	if len(out.Grants) != 1 {
		t.Fatalf("expected 1 grant, got %d", len(out.Grants))
	}
	if out.Grants[0].Role.Name != "secret-reader" {
		t.Errorf("role name = %q", out.Grants[0].Role.Name)
	}
	if got := out.Grants[0].MatchingRule.Verbs; len(got) != 1 || got[0] != "get" {
		t.Errorf("matchingRule verbs = %v", got)
	}
}

func TestJSONPrinterNonResourceURL(t *testing.T) {
	result := &rbac.PermissionResult{
		Allowed: false,
		Subject: rbac.Subject{Kind: "User", Name: "alice"},
		Request: rbac.PermissionRequest{Verb: "get", NonResourceURL: "/healthz"},
	}

	var buf bytes.Buffer
	if err := (&JSONPrinter{}).Print(&buf, result, nil); err != nil {
		t.Fatalf("Print error: %v", err)
	}

	var out JSONOutput
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if out.Request.NonResourceURL != "/healthz" {
		t.Errorf("expected nonResourceURL /healthz, got %q", out.Request.NonResourceURL)
	}
}
