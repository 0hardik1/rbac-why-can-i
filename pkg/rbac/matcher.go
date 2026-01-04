package rbac

import (
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

	// Check resource name match (if specified in rule)
	if len(rule.ResourceNames) > 0 && request.ResourceName != "" {
		if !matchesResourceName(rule.ResourceNames, request.ResourceName) {
			return false
		}
	}

	// If rule has resourceNames but request doesn't specify one,
	// the rule still applies (it grants access to specific resources)
	// For a "can-i" check without resource name, we assume it could match

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

// matchesResource checks if the requested resource (with subresource) matches any of the rule resources
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

		// Exact match
		if r == fullResource {
			return true
		}

		// Handle wildcard subresource: "pods/*" matches "pods/log", "pods/exec", etc.
		if requestSubresource != "" {
			if r == requestResource+"/*" {
				return true
			}
		}

		// If request has no subresource but rule is for base resource
		if requestSubresource == "" && r == requestResource {
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

// GetImplicitGroups returns the implicit groups a subject belongs to
func GetImplicitGroups(subject Subject) []string {
	groups := []string{"system:authenticated"}

	if subject.Kind == "ServiceAccount" {
		groups = append(groups,
			"system:serviceaccounts",
			"system:serviceaccounts:"+subject.Namespace,
		)
	}

	return groups
}
