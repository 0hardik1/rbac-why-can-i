package rbac

import (
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
)

// RuleMatches reports whether a PolicyRule grants the requested permission.
//
// Verb, API group, resource, and non-resource-URL matching mirror the upstream
// Kubernetes RBAC authorizer so that answers agree with what the live cluster
// would decide. ResourceNames is treated as a "could match" check: a rule
// scoped to specific names still matches a request that omits a resource name
// (see the comment on that branch).
func RuleMatches(rule rbacv1.PolicyRule, request PermissionRequest) bool {
	// Non-resource URL request (e.g. /healthz, /metrics). Only the verb and
	// the URL are relevant; API group and resource don't apply, and such
	// access is grantable only via ClusterRoles.
	if request.NonResourceURL != "" {
		return matchesVerb(rule.Verbs, request.Verb) &&
			matchesNonResourceURL(rule.NonResourceURLs, request.NonResourceURL)
	}

	// Check verb match
	if !matchesVerb(rule.Verbs, request.Verb) {
		return false
	}

	// Check API group match
	if !matchesAPIGroup(rule.APIGroups, request.APIGroup) {
		return false
	}

	// Check resource match (including subresource)
	if !matchesResource(rule.Resources, request.Resource, request.Subresource) {
		return false
	}

	// ResourceNames restricts a rule to specific named objects. Only reject
	// when the request names a specific object that the rule's list excludes.
	// When the request omits a name (a "can-i"-style check), a name-scoped
	// rule is reported as a possible match rather than excluded.
	if len(rule.ResourceNames) > 0 && request.ResourceName != "" {
		if !matchesResourceName(rule.ResourceNames, request.ResourceName) {
			return false
		}
	}

	return true
}

// matchesVerb reports whether the requested verb is allowed by the rule.
func matchesVerb(ruleVerbs []string, requestVerb string) bool {
	for _, v := range ruleVerbs {
		if v == rbacv1.VerbAll || v == requestVerb {
			return true
		}
	}
	return false
}

// matchesAPIGroup reports whether the requested API group is allowed by the
// rule. The core API group is the empty string "".
func matchesAPIGroup(ruleGroups []string, requestGroup string) bool {
	for _, g := range ruleGroups {
		if g == rbacv1.APIGroupAll || g == requestGroup {
			return true
		}
	}
	return false
}

// matchesResource reports whether the requested resource (optionally with a
// subresource) is allowed by the rule. This mirrors the upstream authorizer's
// resourceMatches: it honors "*" (all resources) and "*/<subresource>" (a
// subresource across all resources, e.g. "*/scale"), and otherwise requires an
// exact match on "<resource>" or "<resource>/<subresource>".
//
// Note: "<resource>/*" (e.g. "pods/*") is NOT a valid RBAC pattern upstream and
// is intentionally not matched, so that a rule granting "pods/*" does not appear
// to grant "pods/exec" when the live cluster would deny it.
func matchesResource(ruleResources []string, requestResource, requestSubresource string) bool {
	// Build the full resource string (e.g., "pods" or "pods/exec").
	combined := requestResource
	if requestSubresource != "" {
		combined = requestResource + "/" + requestSubresource
	}

	for _, r := range ruleResources {
		// "*" matches every resource.
		if r == rbacv1.ResourceAll {
			return true
		}
		// Exact match on "<resource>" or "<resource>/<subresource>".
		if r == combined {
			return true
		}
		// "*/<subresource>" matches the requested subresource on any resource.
		if requestSubresource == "" {
			continue
		}
		if len(r) == len(requestSubresource)+2 &&
			strings.HasPrefix(r, "*/") &&
			strings.HasSuffix(r, requestSubresource) {
			return true
		}
	}
	return false
}

// matchesResourceName reports whether the requested resource name is in the
// rule's ResourceNames list.
func matchesResourceName(ruleNames []string, requestName string) bool {
	for _, n := range ruleNames {
		if n == requestName {
			return true
		}
	}
	return false
}

// matchesNonResourceURL reports whether the requested non-resource URL is
// allowed by the rule. Mirrors the upstream authorizer's nonResourceURLMatches:
// "*" matches any URL, and a trailing-star rule like "/api/*" matches any path
// with that prefix.
func matchesNonResourceURL(ruleURLs []string, requestURL string) bool {
	for _, u := range ruleURLs {
		if u == rbacv1.NonResourceAll {
			return true
		}
		if u == requestURL {
			return true
		}
		if strings.HasSuffix(u, "*") && strings.HasPrefix(requestURL, strings.TrimRight(u, "*")) {
			return true
		}
	}
	return false
}

// SubjectMatches checks if a binding subject matches the request subject
func SubjectMatches(bindingSubject rbacv1.Subject, requestSubject Subject) bool {
	if bindingSubject.Kind != requestSubject.Kind {
		return false
	}

	if bindingSubject.Name != requestSubject.Name {
		return false
	}

	// For ServiceAccounts, namespace must also match
	if requestSubject.Kind == "ServiceAccount" {
		if bindingSubject.Namespace != requestSubject.Namespace {
			return false
		}
	}

	return true
}

// SubjectMatchesWithGroups checks if a binding subject matches the request subject
// or any of the subject's groups
func SubjectMatchesWithGroups(bindingSubject rbacv1.Subject, requestSubject Subject, groups []string) bool {
	// Direct subject match
	if SubjectMatches(bindingSubject, requestSubject) {
		return true
	}

	// Check if binding is for a group that the subject belongs to
	if bindingSubject.Kind == "Group" {
		for _, group := range groups {
			if bindingSubject.Name == group {
				return true
			}
		}
	}

	return false
}

// GetImplicitGroups returns all groups a subject belongs to (explicit + implicit)
func GetImplicitGroups(subject Subject) []string {
	// Start with explicit groups from the subject (e.g., from client certificate)
	groups := make([]string, 0, len(subject.Groups)+3)
	groups = append(groups, subject.Groups...)

	// Add implicit groups
	groups = append(groups, "system:authenticated")

	if subject.Kind == "ServiceAccount" {
		groups = append(groups,
			"system:serviceaccounts",
			"system:serviceaccounts:"+subject.Namespace,
		)
	}

	return groups
}
