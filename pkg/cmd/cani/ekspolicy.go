package cani

import (
	"context"
	"fmt"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/hardik/kubectl-rbac-why/pkg/client"
	"github.com/hardik/kubectl-rbac-why/pkg/rbac"
)

// EKS access policies grant Kubernetes permissions additively with RBAC, so
// they must participate in allow/deny results and risk analysis. AWS
// documents each managed policy as equivalent to one of the well-known
// Kubernetes roles: https://docs.aws.amazon.com/eks/latest/userguide/access-policies.html
//
// Policies mapping to an aggregated ClusterRole (admin/edit/view) are
// resolved by fetching that ClusterRole from the cluster, so the evaluated
// rules match what the cluster actually aggregates.
var eksPolicyClusterRoles = map[string]string{
	"AmazonEKSAdminPolicy": "admin",
	"AmazonEKSEditPolicy":  "edit",
	"AmazonEKSViewPolicy":  "view",
}

// eksPolicySyntheticRules covers policies whose rules are fixed and don't
// correspond to a ClusterRole present on every cluster.
var eksPolicySyntheticRules = map[string][]rbacv1.PolicyRule{
	// Cluster-admin equivalent.
	"AmazonEKSClusterAdminPolicy": {{
		Verbs:     []string{rbacv1.VerbAll},
		APIGroups: []string{rbacv1.APIGroupAll},
		Resources: []string{rbacv1.ResourceAll},
	}},
	// Read-only access to all resources, including Secrets.
	"AmazonEKSAdminViewPolicy": {{
		Verbs:     []string{"get", "list", "watch"},
		APIGroups: []string{rbacv1.APIGroupAll},
		Resources: []string{rbacv1.ResourceAll},
	}},
}

// accessPolicyName extracts the trailing policy name from an access policy
// ARN (arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy).
func accessPolicyName(policyARN string) string {
	if idx := strings.LastIndex(policyARN, "/"); idx != -1 {
		return policyARN[idx+1:]
	}
	return policyARN
}

// accessPolicyScope reports whether the policy's access scope covers the
// requested namespace, and the grant scope it produces. namespace == ""
// means a cluster-scoped request, which only cluster-scoped policies cover.
func accessPolicyScope(ap AccessPolicyAssociation, namespace string) (bool, rbac.GrantScope) {
	switch ap.ScopeType {
	case "cluster", "":
		return true, rbac.ScopeClusterWide
	case "namespace":
		if namespace == "" {
			return false, rbac.ScopeNamespace
		}
		for _, ns := range ap.Namespaces {
			if ns == namespace {
				return true, rbac.ScopeNamespace
			}
			// EKS allows a trailing wildcard in scope namespaces (e.g. "dev-*").
			if strings.HasSuffix(ns, "*") && strings.HasPrefix(namespace, strings.TrimSuffix(ns, "*")) {
				return true, rbac.ScopeNamespace
			}
		}
		return false, rbac.ScopeNamespace
	default:
		return false, rbac.ScopeClusterWide
	}
}

// resolveAccessPolicyRules returns the effective Kubernetes rules for a
// managed access policy, fetching the equivalent ClusterRole when needed.
func resolveAccessPolicyRules(ctx context.Context, rbacClient client.RBACClient, policyARN string) ([]rbacv1.PolicyRule, error) {
	name := accessPolicyName(policyARN)
	if rules, ok := eksPolicySyntheticRules[name]; ok {
		return rules, nil
	}
	if clusterRole, ok := eksPolicyClusterRoles[name]; ok {
		cr, err := rbacClient.GetClusterRole(ctx, clusterRole)
		if err != nil {
			return nil, fmt.Errorf("failed to get ClusterRole %s (equivalent of access policy %s): %w", clusterRole, name, err)
		}
		return cr.Rules, nil
	}
	return nil, fmt.Errorf("access policy %s is not recognized; its permissions were not evaluated", policyARN)
}

// accessPolicyGrants evaluates the subject's EKS access policies. When
// request is non-nil only rules matching the request are returned; with a nil
// request every rule is returned (used by --show-risky, gated on namespace).
// Returned errors mean the evaluation is incomplete.
func accessPolicyGrants(ctx context.Context, rbacClient client.RBACClient, policies []AccessPolicyAssociation, principalARN, namespace string, request *rbac.PermissionRequest) ([]rbac.PermissionGrant, []error) {
	var grants []rbac.PermissionGrant
	var errs []error

	for _, ap := range policies {
		applies, scope := accessPolicyScope(ap, namespace)
		if !applies {
			continue
		}

		rules, err := resolveAccessPolicyRules(ctx, rbacClient, ap.PolicyARN)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		for _, rule := range rules {
			if request != nil && !rbac.RuleMatches(rule, *request) {
				continue
			}
			grants = append(grants, rbac.PermissionGrant{
				Binding: rbac.BindingInfo{
					Kind: "EKSAccessEntry",
					Name: principalARN,
				},
				Role: rbac.RoleInfo{
					Kind: "EKSAccessPolicy",
					Name: accessPolicyName(ap.PolicyARN),
				},
				MatchingRule: rule,
				Scope:        scope,
			})
		}
	}

	return grants, errs
}
