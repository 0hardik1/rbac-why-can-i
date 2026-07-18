package cani

import (
	"context"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/hardik/kubectl-rbac-why/pkg/client"
	"github.com/hardik/kubectl-rbac-why/pkg/rbac"
)

const clusterAdminPolicyARN = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
const viewPolicyARN = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"

func TestAccessPolicyGrants_ClusterAdminAllowsRequest(t *testing.T) {
	mock := client.NewMockRBACClient()
	request := rbac.PermissionRequest{Verb: "delete", APIGroup: "apps", Resource: "deployments", Namespace: "prod"}
	grants, errs := accessPolicyGrants(context.Background(), mock,
		[]AccessPolicyAssociation{{PolicyARN: clusterAdminPolicyARN, ScopeType: "cluster"}},
		"arn:aws:iam::1:role/admin", request.Namespace, &request)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(grants) != 1 {
		t.Fatalf("expected 1 grant, got %d", len(grants))
	}
	g := grants[0]
	if g.Binding.Kind != "EKSAccessEntry" || g.Role.Kind != "EKSAccessPolicy" || g.Role.Name != "AmazonEKSClusterAdminPolicy" {
		t.Errorf("unexpected grant shape: %+v", g)
	}
	if g.Scope != rbac.ScopeClusterWide {
		t.Errorf("expected cluster-wide scope, got %s", g.Scope)
	}
}

func TestAccessPolicyGrants_NamespaceScopeGates(t *testing.T) {
	mock := client.NewMockRBACClient()
	policies := []AccessPolicyAssociation{{
		PolicyARN:  clusterAdminPolicyARN,
		ScopeType:  "namespace",
		Namespaces: []string{"team-a"},
	}}
	request := rbac.PermissionRequest{Verb: "get", APIGroup: "", Resource: "pods", Namespace: "team-b"}
	grants, errs := accessPolicyGrants(context.Background(), mock, policies, "arn", request.Namespace, &request)
	if len(errs) != 0 || len(grants) != 0 {
		t.Fatalf("policy scoped to team-a must not grant in team-b: grants=%v errs=%v", grants, errs)
	}

	request.Namespace = "team-a"
	grants, errs = accessPolicyGrants(context.Background(), mock, policies, "arn", request.Namespace, &request)
	if len(errs) != 0 || len(grants) != 1 {
		t.Fatalf("expected 1 grant in team-a: grants=%v errs=%v", grants, errs)
	}
	if grants[0].Scope != rbac.ScopeNamespace {
		t.Errorf("expected namespace scope, got %s", grants[0].Scope)
	}

	// Namespace-scoped policies never cover cluster-scoped requests.
	request.Namespace = ""
	request.Resource = "nodes"
	grants, _ = accessPolicyGrants(context.Background(), mock, policies, "arn", "", &request)
	if len(grants) != 0 {
		t.Fatalf("namespace-scoped policy must not cover a cluster-scoped request, got %v", grants)
	}
}

func TestAccessPolicyGrants_ViewPolicyUsesClusterRole(t *testing.T) {
	mock := client.NewMockRBACClient()
	mock.AddClusterRole(rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "view"},
		Rules: []rbacv1.PolicyRule{{
			Verbs:     []string{"get", "list", "watch"},
			APIGroups: []string{""},
			Resources: []string{"pods", "configmaps"},
		}},
	})
	request := rbac.PermissionRequest{Verb: "get", APIGroup: "", Resource: "pods", Namespace: "default"}
	grants, errs := accessPolicyGrants(context.Background(), mock,
		[]AccessPolicyAssociation{{PolicyARN: viewPolicyARN, ScopeType: "cluster"}},
		"arn", request.Namespace, &request)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(grants) != 1 {
		t.Fatalf("expected 1 grant via ClusterRole view, got %d", len(grants))
	}

	// view does not grant secrets
	request.Resource = "secrets"
	grants, errs = accessPolicyGrants(context.Background(), mock,
		[]AccessPolicyAssociation{{PolicyARN: viewPolicyARN, ScopeType: "cluster"}},
		"arn", request.Namespace, &request)
	if len(errs) != 0 || len(grants) != 0 {
		t.Fatalf("view policy must not grant secrets: grants=%v errs=%v", grants, errs)
	}
}

func TestAccessPolicyGrants_UnknownPolicyReportsError(t *testing.T) {
	mock := client.NewMockRBACClient()
	request := rbac.PermissionRequest{Verb: "get", APIGroup: "", Resource: "pods", Namespace: "default"}
	grants, errs := accessPolicyGrants(context.Background(), mock,
		[]AccessPolicyAssociation{{PolicyARN: "arn:aws:eks::aws:cluster-access-policy/SomeFuturePolicy", ScopeType: "cluster"}},
		"arn", request.Namespace, &request)
	if len(grants) != 0 {
		t.Fatalf("unknown policy must not produce grants, got %v", grants)
	}
	if len(errs) != 1 {
		t.Fatalf("unknown policy must be reported as an error, got %v", errs)
	}
}

func TestAccessPolicyGrants_NilRequestReturnsAllRules(t *testing.T) {
	mock := client.NewMockRBACClient()
	grants, errs := accessPolicyGrants(context.Background(), mock,
		[]AccessPolicyAssociation{{PolicyARN: clusterAdminPolicyARN, ScopeType: "cluster"}},
		"arn", "default", nil)
	if len(errs) != 0 || len(grants) != 1 {
		t.Fatalf("expected all rules as grants: grants=%v errs=%v", grants, errs)
	}
	if grants[0].MatchingRule.Verbs[0] != rbacv1.VerbAll {
		t.Errorf("expected wildcard rule, got %+v", grants[0].MatchingRule)
	}
}
