package output

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/hardik/kubectl-rbac-why/pkg/rbac"
)

func TestTextPrinter_IncompleteNotDenied(t *testing.T) {
	result := &rbac.PermissionResult{
		Allowed: false,
		Subject: rbac.Subject{Kind: "User", Name: "jane"},
		Request: rbac.PermissionRequest{Verb: "get", Resource: "pods"},
		Errors:  []error{errors.New("failed to get cluster role broken-ref")},
	}
	var buf bytes.Buffer
	if err := (&TextPrinter{}).Print(&buf, result, nil); err != nil {
		t.Fatalf("Print: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, "INCOMPLETE") {
		t.Errorf("expected INCOMPLETE, got:\n%s", got)
	}
	if strings.Contains(got, "DENIED") {
		t.Errorf("must not report DENIED when resolution is incomplete, got:\n%s", got)
	}
	if !strings.Contains(got, "broken-ref") {
		t.Errorf("expected the underlying error to be shown, got:\n%s", got)
	}
}

func TestTextPrinter_DeniedWhenComplete(t *testing.T) {
	result := &rbac.PermissionResult{
		Allowed: false,
		Subject: rbac.Subject{Kind: "User", Name: "jane"},
		Request: rbac.PermissionRequest{Verb: "get", Resource: "pods"},
	}
	var buf bytes.Buffer
	if err := (&TextPrinter{}).Print(&buf, result, nil); err != nil {
		t.Fatalf("Print: %v", err)
	}
	if !strings.Contains(buf.String(), "DENIED") {
		t.Errorf("expected DENIED, got:\n%s", buf.String())
	}
}

func TestYAMLPrinter_HonorsJSONFieldNames(t *testing.T) {
	result := &rbac.PermissionResult{
		Allowed: true,
		Subject: rbac.Subject{Kind: "User", Name: "jane"},
		Request: rbac.PermissionRequest{Verb: "get", APIGroup: "apps", Resource: "deployments"},
		Grants: []rbac.PermissionGrant{{
			Binding: rbac.BindingInfo{Kind: "ClusterRoleBinding", Name: "b"},
			Role:    rbac.RoleInfo{Kind: "ClusterRole", Name: "r"},
			MatchingRule: rbacv1.PolicyRule{
				Verbs:         []string{"get"},
				APIGroups:     []string{"apps"},
				Resources:     []string{"deployments"},
				ResourceNames: []string{"web"},
			},
			Scope: rbac.ScopeClusterWide,
		}},
	}
	var buf bytes.Buffer
	if err := (&YAMLPrinter{}).Print(&buf, result, nil); err != nil {
		t.Fatalf("Print: %v", err)
	}
	got := buf.String()
	for _, want := range []string{"apiGroup:", "matchingRule:", "resourceNames:", "apiGroups:"} {
		if !strings.Contains(got, want) {
			t.Errorf("YAML output missing documented field %q, got:\n%s", want, got)
		}
	}
	for _, reject := range []string{"apigroup:", "matchingrule:", "resourcenames:"} {
		if strings.Contains(got, reject) {
			t.Errorf("YAML output contains lowercased field %q, got:\n%s", reject, got)
		}
	}
	// omitempty must apply: no subresource/namespace fields were set
	if strings.Contains(got, "subresource:") {
		t.Errorf("omitempty not honored for empty subresource, got:\n%s", got)
	}
}
