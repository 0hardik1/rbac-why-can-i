package output

import (
	"bytes"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/hardik/kubectl-rbac-why/pkg/rbac"
)

func TestTextPrinter_RendersEKSContextBlock(t *testing.T) {
	ctx := &ContextInfo{
		ContextName:    "arn:aws:eks:us-east-1:123:cluster/prod",
		ClusterName:    "arn:aws:eks:us-east-1:123:cluster/prod",
		AuthInfo:       "auth",
		UserName:       "admin@example.com",
		AuthMethod:     "aws-iam (via Access Entry)",
		EKSClusterName: "prod",
		AccessPolicies: []AccessPolicyInfo{{
			PolicyARN: "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy",
			ScopeType: "cluster",
		}},
		PodIdentityForSA: []PodIdentityInfo{{
			AssociationID:  "a-1",
			Namespace:      "default",
			ServiceAccount: "my-sa",
			RoleARN:        "arn:aws:iam::123:role/MyRole",
		}},
	}
	result := &rbac.PermissionResult{
		Allowed: false,
		Subject: rbac.Subject{Kind: "User", Name: "admin@example.com"},
		Request: rbac.PermissionRequest{Verb: "get", Resource: "pods"},
	}
	var buf bytes.Buffer
	if err := (&TextPrinter{}).Print(&buf, result, ctx); err != nil {
		t.Fatalf("Print: %v", err)
	}
	got := buf.String()
	for _, want := range []string{
		"AWS / EKS identity:",
		"EKS Cluster: prod",
		"AmazonEKSClusterAdminPolicy",
		"scope: cluster",
		"Pod Identity associations for this ServiceAccount",
		"arn:aws:iam::123:role/MyRole",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\n--- got ---\n%s", want, got)
		}
	}
}

func TestTextPrinter_NoEKSBlockWhenEmpty(t *testing.T) {
	ctx := &ContextInfo{ContextName: "kind", ClusterName: "kind", AuthInfo: "kind", UserName: "kubernetes-admin"}
	result := &rbac.PermissionResult{
		Allowed: true,
		Subject: rbac.Subject{Kind: "User", Name: "kubernetes-admin"},
		Request: rbac.PermissionRequest{Verb: "get", Resource: "pods"},
		Grants: []rbac.PermissionGrant{{
			Binding: rbac.BindingInfo{Kind: "ClusterRoleBinding", Name: "cluster-admin"},
			Role:    rbac.RoleInfo{Kind: "ClusterRole", Name: "cluster-admin"},
			MatchingRule: rbacv1.PolicyRule{
				Verbs:     []string{"*"},
				APIGroups: []string{"*"},
				Resources: []string{"*"},
			},
			Scope: rbac.ScopeClusterWide,
		}},
	}
	var buf bytes.Buffer
	if err := (&TextPrinter{}).Print(&buf, result, ctx); err != nil {
		t.Fatalf("Print: %v", err)
	}
	if strings.Contains(buf.String(), "AWS / EKS identity") {
		t.Errorf("EKS block should not appear without EKS fields; got:\n%s", buf.String())
	}
}
