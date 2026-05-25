package rbac

import (
	"context"
	"fmt"
	"sort"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/hardik/kubectl-rbac-why/pkg/client"
)

// Resolver handles RBAC permission resolution
type Resolver struct {
	client client.RBACClient
}

// NewResolver creates a new RBAC resolver
func NewResolver(c client.RBACClient) *Resolver {
	return &Resolver{client: c}
}

// ParseSubject parses a --as string into a Subject
func ParseSubject(asString string) (Subject, error) {
	if asString == "" {
		return Subject{}, fmt.Errorf("subject cannot be empty")
	}

	// Format: "system:serviceaccount:namespace:name"
	if strings.HasPrefix(asString, "system:serviceaccount:") {
		parts := strings.Split(asString, ":")
		if len(parts) != 4 {
			return Subject{}, fmt.Errorf("invalid serviceaccount format: %s (expected system:serviceaccount:namespace:name)", asString)
		}
		return Subject{
			Kind:      "ServiceAccount",
			Namespace: parts[2],
			Name:      parts[3],
		}, nil
	}

	// Groups typically start with "system:" but aren't serviceaccounts
	if strings.HasPrefix(asString, "system:") {
		return Subject{
			Kind: "Group",
			Name: asString,
		}, nil
	}

	// Otherwise treat as User
	return Subject{
		Kind: "User",
		Name: asString,
	}, nil
}

// ResolvePermission finds all grants for a permission request
func (r *Resolver) ResolvePermission(ctx context.Context, subject Subject, request PermissionRequest) (*PermissionResult, error) {
	result := &PermissionResult{
		Request: request,
		Subject: subject,
		Grants:  []PermissionGrant{},
	}

	// Get implicit groups for the subject
	groups := GetImplicitGroups(subject)

	// Find all ClusterRoleBindings that reference this subject
	crbs, err := r.client.ListClusterRoleBindings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster role bindings: %w", err)
	}

	for _, crb := range crbs.Items {
		if !r.bindingMatchesSubject(crb.Subjects, subject, groups) {
			continue
		}

		// Get the referenced ClusterRole
		clusterRole, err := r.client.GetClusterRole(ctx, crb.RoleRef.Name)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("failed to get cluster role %s: %w", crb.RoleRef.Name, err))
			continue
		}

		// Check each rule in the role
		for _, rule := range clusterRole.Rules {
			if RuleMatches(rule, request) {
				grant := PermissionGrant{
					Binding: BindingInfo{
						Kind: "ClusterRoleBinding",
						Name: crb.Name,
					},
					Role: RoleInfo{
						Kind: "ClusterRole",
						Name: clusterRole.Name,
					},
					MatchingRule: rule,
					Scope:        ScopeClusterWide,
				}
				result.Grants = append(result.Grants, grant)
			}
		}
	}

	// If namespace is specified, also check RoleBindings in that namespace.
	// Non-resource URL requests (e.g. /healthz) carry no namespace on a real
	// cluster and are authorized only via ClusterRoleBindings, so a RoleBinding
	// must never grant them, even one referencing a ClusterRole that lists
	// nonResourceURLs. Skip the RoleBinding scan to avoid a false grant.
	if request.NonResourceURL == "" && request.Namespace != "" {
		rbs, err := r.client.ListRoleBindings(ctx, request.Namespace)
		if err != nil {
			return nil, fmt.Errorf("failed to list role bindings in namespace %s: %w", request.Namespace, err)
		}

		for _, rb := range rbs.Items {
			if !r.bindingMatchesSubject(rb.Subjects, subject, groups) {
				continue
			}

			var rules []rbacv1.PolicyRule
			var roleInfo RoleInfo

			// RoleBinding can reference either a Role or ClusterRole
			if rb.RoleRef.Kind == "ClusterRole" {
				clusterRole, err := r.client.GetClusterRole(ctx, rb.RoleRef.Name)
				if err != nil {
					result.Errors = append(result.Errors, fmt.Errorf("failed to get cluster role %s: %w", rb.RoleRef.Name, err))
					continue
				}
				rules = clusterRole.Rules
				roleInfo = RoleInfo{
					Kind: "ClusterRole",
					Name: clusterRole.Name,
				}
			} else {
				role, err := r.client.GetRole(ctx, request.Namespace, rb.RoleRef.Name)
				if err != nil {
					result.Errors = append(result.Errors, fmt.Errorf("failed to get role %s in namespace %s: %w", rb.RoleRef.Name, request.Namespace, err))
					continue
				}
				rules = role.Rules
				roleInfo = RoleInfo{
					Kind:      "Role",
					Name:      role.Name,
					Namespace: role.Namespace,
				}
			}

			// Check each rule
			for _, rule := range rules {
				if RuleMatches(rule, request) {
					grant := PermissionGrant{
						Binding: BindingInfo{
							Kind:      "RoleBinding",
							Name:      rb.Name,
							Namespace: rb.Namespace,
						},
						Role:         roleInfo,
						MatchingRule: rule,
						Scope:        ScopeNamespace,
					}
					result.Grants = append(result.Grants, grant)
				}
			}
		}
	}

	result.Allowed = len(result.Grants) > 0
	return result, nil
}

// bindingMatchesSubject checks if any subject in the binding matches the request subject
func (r *Resolver) bindingMatchesSubject(subjects []rbacv1.Subject, subject Subject, groups []string) bool {
	for _, s := range subjects {
		if SubjectMatchesWithGroups(s, subject, groups) {
			return true
		}
	}
	return false
}

// ResolveAllPermissions gets all permissions for a subject (for risky
// permission analysis).
//
// It returns the matched grants, a slice of non-fatal "soft" errors (e.g. a
// referenced Role/ClusterRole that could not be read because it was deleted or
// the caller lacks access), and a fatal error if listing bindings failed.
// Soft errors are returned rather than dropped so a risk scan does not silently
// report a clean result while having skipped roles it could not read.
func (r *Resolver) ResolveAllPermissions(ctx context.Context, subject Subject, namespace string, allNamespaces bool) ([]PermissionGrant, []error, error) {
	var grants []PermissionGrant
	var softErrors []error
	groups := GetImplicitGroups(subject)

	// Get all ClusterRoleBindings
	crbs, err := r.client.ListClusterRoleBindings(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list cluster role bindings: %w", err)
	}

	for _, crb := range crbs.Items {
		if !r.bindingMatchesSubject(crb.Subjects, subject, groups) {
			continue
		}

		clusterRole, err := r.client.GetClusterRole(ctx, crb.RoleRef.Name)
		if err != nil {
			softErrors = append(softErrors, fmt.Errorf("failed to get cluster role %s: %w", crb.RoleRef.Name, err))
			continue
		}

		for _, rule := range clusterRole.Rules {
			grant := PermissionGrant{
				Binding: BindingInfo{
					Kind: "ClusterRoleBinding",
					Name: crb.Name,
				},
				Role: RoleInfo{
					Kind: "ClusterRole",
					Name: clusterRole.Name,
				},
				MatchingRule: rule,
				Scope:        ScopeClusterWide,
			}
			grants = append(grants, grant)
		}
	}

	// Scan RoleBindings: in the given namespace, or across all namespaces when
	// requested. Each binding's own namespace is used to fetch its Role.
	if allNamespaces || namespace != "" {
		listNamespace := namespace
		if allNamespaces {
			listNamespace = "" // empty namespace lists across all namespaces
		}
		rbs, err := r.client.ListRoleBindings(ctx, listNamespace)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to list role bindings: %w", err)
		}

		for _, rb := range rbs.Items {
			if !r.bindingMatchesSubject(rb.Subjects, subject, groups) {
				continue
			}

			var rules []rbacv1.PolicyRule
			var roleInfo RoleInfo

			if rb.RoleRef.Kind == "ClusterRole" {
				clusterRole, err := r.client.GetClusterRole(ctx, rb.RoleRef.Name)
				if err != nil {
					softErrors = append(softErrors, fmt.Errorf("failed to get cluster role %s: %w", rb.RoleRef.Name, err))
					continue
				}
				rules = clusterRole.Rules
				roleInfo = RoleInfo{Kind: "ClusterRole", Name: clusterRole.Name}
			} else {
				role, err := r.client.GetRole(ctx, rb.Namespace, rb.RoleRef.Name)
				if err != nil {
					softErrors = append(softErrors, fmt.Errorf("failed to get role %s in namespace %s: %w", rb.RoleRef.Name, rb.Namespace, err))
					continue
				}
				rules = role.Rules
				roleInfo = RoleInfo{Kind: "Role", Name: role.Name, Namespace: role.Namespace}
			}

			for _, rule := range rules {
				grant := PermissionGrant{
					Binding: BindingInfo{
						Kind:      "RoleBinding",
						Name:      rb.Name,
						Namespace: rb.Namespace,
					},
					Role:         roleInfo,
					MatchingRule: rule,
					Scope:        ScopeNamespace,
				}
				grants = append(grants, grant)
			}
		}
	}

	return grants, softErrors, nil
}

// firstMatchingRule returns the first rule in the list that grants the request,
// and whether one was found.
func firstMatchingRule(rules []rbacv1.PolicyRule, request PermissionRequest) (rbacv1.PolicyRule, bool) {
	for _, rule := range rules {
		if RuleMatches(rule, request) {
			return rule, true
		}
	}
	return rbacv1.PolicyRule{}, false
}

// ResolveSubjectsWithPermission finds every subject that can perform the
// requested permission. It is the inverse of ResolvePermission ("who can do X"
// rather than "why can this subject do X"). It scans ClusterRoleBindings
// cluster-wide and, when request.Namespace is set, RoleBindings in that
// namespace, collecting the subjects bound to any role whose rules grant the
// permission.
func (r *Resolver) ResolveSubjectsWithPermission(ctx context.Context, request PermissionRequest) (*ReverseResult, error) {
	result := &ReverseResult{Request: request}

	// ClusterRoles whose rules grant the permission (name -> matching rule).
	matchingClusterRoles := make(map[string]rbacv1.PolicyRule)
	crs, err := r.client.ListClusterRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster roles: %w", err)
	}
	for _, cr := range crs.Items {
		if rule, ok := firstMatchingRule(cr.Rules, request); ok {
			matchingClusterRoles[cr.Name] = rule
		}
	}

	// Roles in the namespace whose rules grant the permission (ns/name -> rule).
	// Non-resource URLs are cluster-scoped only: namespaced Roles can't carry
	// them and RoleBindings never grant them, so skip the namespaced scan for
	// such requests (see ResolvePermission for the same invariant).
	matchingRoles := make(map[string]rbacv1.PolicyRule)
	if request.NonResourceURL == "" && request.Namespace != "" {
		roles, err := r.client.ListRoles(ctx, request.Namespace)
		if err != nil {
			return nil, fmt.Errorf("failed to list roles in namespace %s: %w", request.Namespace, err)
		}
		for _, role := range roles.Items {
			if rule, ok := firstMatchingRule(role.Rules, request); ok {
				matchingRoles[role.Namespace+"/"+role.Name] = rule
			}
		}
	}

	agg := newSubjectAggregator()

	// ClusterRoleBindings referencing a matching ClusterRole (cluster-wide).
	crbs, err := r.client.ListClusterRoleBindings(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster role bindings: %w", err)
	}
	for _, crb := range crbs.Items {
		rule, ok := matchingClusterRoles[crb.RoleRef.Name]
		if crb.RoleRef.Kind != "ClusterRole" || !ok {
			continue
		}
		for _, s := range crb.Subjects {
			agg.add(s, PermissionGrant{
				Binding:      BindingInfo{Kind: "ClusterRoleBinding", Name: crb.Name},
				Role:         RoleInfo{Kind: "ClusterRole", Name: crb.RoleRef.Name},
				MatchingRule: rule,
				Scope:        ScopeClusterWide,
			})
		}
	}

	// RoleBindings in the namespace referencing a matching Role or ClusterRole.
	// Skipped for non-resource URLs (cluster-scoped only; see above).
	if request.NonResourceURL == "" && request.Namespace != "" {
		rbs, err := r.client.ListRoleBindings(ctx, request.Namespace)
		if err != nil {
			return nil, fmt.Errorf("failed to list role bindings in namespace %s: %w", request.Namespace, err)
		}
		for _, rb := range rbs.Items {
			var (
				roleInfo RoleInfo
				rule     rbacv1.PolicyRule
				ok       bool
			)
			switch rb.RoleRef.Kind {
			case "ClusterRole":
				rule, ok = matchingClusterRoles[rb.RoleRef.Name]
				roleInfo = RoleInfo{Kind: "ClusterRole", Name: rb.RoleRef.Name}
			case "Role":
				rule, ok = matchingRoles[rb.Namespace+"/"+rb.RoleRef.Name]
				roleInfo = RoleInfo{Kind: "Role", Name: rb.RoleRef.Name, Namespace: rb.Namespace}
			}
			if !ok {
				continue
			}
			for _, s := range rb.Subjects {
				agg.add(s, PermissionGrant{
					Binding:      BindingInfo{Kind: "RoleBinding", Name: rb.Name, Namespace: rb.Namespace},
					Role:         roleInfo,
					MatchingRule: rule,
					Scope:        ScopeNamespace,
				})
			}
		}
	}

	result.Subjects = agg.list()
	return result, nil
}

// subjectAggregator collects grants per unique subject, preserving first-seen
// order so output is stable.
type subjectAggregator struct {
	order []string
	byKey map[string]*SubjectGrant
}

func newSubjectAggregator() *subjectAggregator {
	return &subjectAggregator{byKey: make(map[string]*SubjectGrant)}
}

func (a *subjectAggregator) add(s rbacv1.Subject, grant PermissionGrant) {
	subj := Subject{Kind: s.Kind, Name: s.Name, Namespace: s.Namespace}
	key := subj.Kind + "\x00" + subj.Namespace + "\x00" + subj.Name
	sg, ok := a.byKey[key]
	if !ok {
		sg = &SubjectGrant{Subject: subj}
		a.byKey[key] = sg
		a.order = append(a.order, key)
	}
	sg.Grants = append(sg.Grants, grant)
}

func (a *subjectAggregator) list() []SubjectGrant {
	out := make([]SubjectGrant, 0, len(a.order))
	for _, k := range a.order {
		out = append(out, *a.byKey[k])
	}
	return out
}

// ComparePermissions compares the effective rules of two subjects, returning
// the rules unique to each and those they share. Rules are compared by a
// canonical key (sorted verbs, API groups, resources, resource names, and
// non-resource URLs), so semantically identical rules from different roles
// match. Soft errors from either resolution are collected on the result.
func (r *Resolver) ComparePermissions(ctx context.Context, a, b Subject, namespace string, allNamespaces bool) (*PermissionComparison, error) {
	aGrants, aSoft, err := r.ResolveAllPermissions(ctx, a, namespace, allNamespaces)
	if err != nil {
		return nil, err
	}
	bGrants, bSoft, err := r.ResolveAllPermissions(ctx, b, namespace, allNamespaces)
	if err != nil {
		return nil, err
	}

	aByKey := groupByRule(aGrants)
	bByKey := groupByRule(bGrants)

	comp := &PermissionComparison{SubjectA: a, SubjectB: b}
	comp.SoftErrors = append(comp.SoftErrors, aSoft...)
	comp.SoftErrors = append(comp.SoftErrors, bSoft...)

	for key, rg := range aByKey {
		if _, ok := bByKey[key]; ok {
			comp.Shared = append(comp.Shared, *rg)
		} else {
			comp.OnlyA = append(comp.OnlyA, *rg)
		}
	}
	for key, rg := range bByKey {
		if _, ok := aByKey[key]; !ok {
			comp.OnlyB = append(comp.OnlyB, *rg)
		}
	}

	sortRuleGrants(comp.OnlyA)
	sortRuleGrants(comp.OnlyB)
	sortRuleGrants(comp.Shared)
	return comp, nil
}

// groupByRule groups grants by a canonical key derived from their matching rule.
func groupByRule(grants []PermissionGrant) map[string]*RuleGrant {
	m := make(map[string]*RuleGrant)
	for _, g := range grants {
		key := canonicalRuleKey(g.MatchingRule)
		rg, ok := m[key]
		if !ok {
			rg = &RuleGrant{Rule: g.MatchingRule}
			m[key] = rg
		}
		rg.Grants = append(rg.Grants, g)
	}
	return m
}

// canonicalRuleKey produces a stable key for a policy rule so that
// semantically identical rules compare equal regardless of field order.
func canonicalRuleKey(rule rbacv1.PolicyRule) string {
	sortedJoin := func(s []string) string {
		out := append([]string(nil), s...)
		sort.Strings(out)
		return strings.Join(out, ",")
	}
	return strings.Join([]string{
		sortedJoin(rule.Verbs),
		sortedJoin(rule.APIGroups),
		sortedJoin(rule.Resources),
		sortedJoin(rule.ResourceNames),
		sortedJoin(rule.NonResourceURLs),
	}, "|")
}

func sortRuleGrants(rgs []RuleGrant) {
	sort.Slice(rgs, func(i, j int) bool {
		return canonicalRuleKey(rgs[i].Rule) < canonicalRuleKey(rgs[j].Rule)
	})
}
