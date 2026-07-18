package rbac

import (
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
)

// RuleMatches checks if a PolicyRule grants the requested permission
func RuleMatches(rule rbacv1.PolicyRule, request PermissionRequest) bool {
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

	// A rule restricted to named objects only grants access to those objects.
	// A request without a name asks about the resource in general (e.g. a
	// list, or a get across all names), which such a rule does not allow.
	if len(rule.ResourceNames) > 0 {
		if request.ResourceName == "" {
			return false
		}
		if !matchesResourceName(rule.ResourceNames, request.ResourceName) {
			return false
		}
	}

	return true
}

// matchesVerb checks if the requested verb matches any of the rule verbs
func matchesVerb(ruleVerbs []string, requestVerb string) bool {
	for _, v := range ruleVerbs {
		if v == rbacv1.VerbAll || v == requestVerb {
			return true
		}
	}
	return false
}

// matchesAPIGroup checks if the requested API group matches any of the rule groups
func matchesAPIGroup(ruleGroups []string, requestGroup string) bool {
	for _, g := range ruleGroups {
		if g == rbacv1.APIGroupAll || g == requestGroup {
			return true
		}
	}
	return false
}

// matchesResource checks if the requested resource (with subresource) matches
// any of the rule resources. Mirrors the upstream RBAC evaluator: "*" matches
// everything, an exact "resource/subresource" string matches, and the special
// "*/subresource" form matches that subresource on any resource. Forms like
// "pods/*" are NOT wildcards in Kubernetes and only match a literal
// subresource named "*".
func matchesResource(ruleResources []string, requestResource, requestSubresource string) bool {
	// Build the full resource string (e.g., "pods" or "pods/exec")
	fullResource := requestResource
	if requestSubresource != "" {
		fullResource = requestResource + "/" + requestSubresource
	}

	for _, r := range ruleResources {
		// Wildcard matches everything
		if r == rbacv1.ResourceAll {
			return true
		}

		// Exact match ("pods", or "pods/exec" against a subresource request)
		if r == fullResource {
			return true
		}

		// "*/subresource" matches the subresource on any resource
		if requestSubresource != "" &&
			len(r) == len(requestSubresource)+2 &&
			strings.HasPrefix(r, "*/") &&
			strings.HasSuffix(r, requestSubresource) {
			return true
		}
	}
	return false
}

// matchesResourceName checks if the requested resource name matches any of the rule names
func matchesResourceName(ruleNames []string, requestName string) bool {
	for _, n := range ruleNames {
		if n == requestName {
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

	switch subject.Kind {
	case "ServiceAccount":
		groups = append(groups,
			"system:authenticated",
			"system:serviceaccounts",
			"system:serviceaccounts:"+subject.Namespace,
		)
	case "User":
		// system:anonymous is the only unauthenticated user; it belongs to
		// system:unauthenticated, never system:authenticated.
		if subject.Name == "system:anonymous" {
			groups = append(groups, "system:unauthenticated")
		} else {
			groups = append(groups, "system:authenticated")
		}
	case "Group":
		// A group subject has no implicit memberships of its own; the group
		// name itself is matched directly against binding subjects.
	}

	return groups
}
