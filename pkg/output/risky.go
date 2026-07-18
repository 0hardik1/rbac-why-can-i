package output

import (
	"fmt"
	"io"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/hardik/kubectl-rbac-why/pkg/rbac"
)

// RiskyPattern defines a dangerous permission pattern
type RiskyPattern struct {
	Category    string
	Severity    string // critical, high, medium
	Description string
	Verbs       []string
	APIGroups   []string
	Resources   []string
}

// RiskyPatterns contains known dangerous permission patterns.
//
// Pattern values are concrete targets, never wildcards: a rule matches a
// pattern when one of its values equals the pattern value OR the rule itself
// carries a wildcard ("*", or "*/subresource" for resources) that covers it.
// The one exception is cluster-admin, where "*" is itself the target: only a
// rule that literally grants "*" on every dimension matches it.
var RiskyPatterns = []RiskyPattern{
	{
		Category:    "secrets-access",
		Severity:    "critical",
		Description: "Access to Secrets can expose sensitive credentials, tokens, and keys",
		Verbs:       []string{"get", "list", "watch"},
		APIGroups:   []string{""},
		Resources:   []string{"secrets"},
	},
	{
		Category:    "pod-exec",
		Severity:    "critical",
		Description: "Pod exec allows arbitrary command execution in containers",
		Verbs:       []string{"create"},
		APIGroups:   []string{""},
		Resources:   []string{"pods/exec"},
	},
	{
		Category:    "pod-attach",
		Severity:    "critical",
		Description: "Pod attach allows connecting to running containers",
		Verbs:       []string{"create"},
		APIGroups:   []string{""},
		Resources:   []string{"pods/attach"},
	},
	{
		Category:    "pod-create",
		Severity:    "high",
		Description: "Pod creation can lead to privilege escalation via hostPath, hostPID, etc.",
		Verbs:       []string{"create"},
		APIGroups:   []string{""},
		Resources:   []string{"pods"},
	},
	{
		Category:    "impersonate",
		Severity:    "critical",
		Description: "Impersonation allows assuming other user/group identities",
		Verbs:       []string{"impersonate"},
		APIGroups:   []string{""},
		Resources:   []string{"users", "groups", "serviceaccounts"},
	},
	{
		Category:    "nodes-proxy",
		Severity:    "critical",
		Description: "Node proxy access can execute commands on nodes via kubelet API",
		Verbs:       []string{"get", "create"},
		APIGroups:   []string{""},
		Resources:   []string{"nodes/proxy"},
	},
	{
		Category:    "persistent-volume-create",
		Severity:    "high",
		Description: "PV creation with hostPath can access node filesystem",
		Verbs:       []string{"create"},
		APIGroups:   []string{""},
		Resources:   []string{"persistentvolumes"},
	},
	{
		Category:    "cluster-admin",
		Severity:    "critical",
		Description: "Wildcard access grants full cluster control (cluster-admin equivalent)",
		Verbs:       []string{"*"},
		APIGroups:   []string{"*"},
		Resources:   []string{"*"},
	},
	{
		Category:    "role-escalation",
		Severity:    "critical",
		Description: "Ability to create/modify roles can escalate privileges",
		Verbs:       []string{"create", "update", "patch", "escalate"},
		APIGroups:   []string{"rbac.authorization.k8s.io"},
		Resources:   []string{"roles", "clusterroles"},
	},
	{
		Category:    "binding-escalation",
		Severity:    "critical",
		Description: "Ability to create/modify bindings can grant any permissions",
		Verbs:       []string{"create", "update", "patch", "bind"},
		APIGroups:   []string{"rbac.authorization.k8s.io"},
		Resources:   []string{"rolebindings", "clusterrolebindings"},
	},
	{
		Category:    "csr-approve",
		Severity:    "high",
		Description: "CSR approval can issue certificates for any identity",
		Verbs:       []string{"update", "approve"},
		APIGroups:   []string{"certificates.k8s.io"},
		Resources:   []string{"certificatesigningrequests/approval"},
	},
	{
		Category:    "token-request",
		Severity:    "high",
		Description: "Token request can generate tokens for any service account",
		Verbs:       []string{"create"},
		APIGroups:   []string{""},
		Resources:   []string{"serviceaccounts/token"},
	},
}

// AnalyzeRiskyPermissions checks grants for risky permission patterns
func AnalyzeRiskyPermissions(grants []rbac.PermissionGrant) []rbac.RiskyPermission {
	var risks []rbac.RiskyPermission
	seenCategories := make(map[string]bool)

	for _, grant := range grants {
		for _, pattern := range RiskyPatterns {
			if matchesRiskyPattern(grant.MatchingRule, pattern) {
				if !seenCategories[pattern.Category] {
					seenCategories[pattern.Category] = true
					risks = append(risks, rbac.RiskyPermission{
						Category:    pattern.Category,
						Description: pattern.Description,
						Severity:    pattern.Severity,
						Grants:      []rbac.PermissionGrant{grant},
					})
				} else {
					// Add to existing risk
					for i := range risks {
						if risks[i].Category == pattern.Category {
							risks[i].Grants = append(risks[i].Grants, grant)
							break
						}
					}
				}
			}
		}
	}

	return risks
}

// matchesRiskyPattern reports whether the rule actually grants what the
// pattern describes. Only rule-side wildcards widen a match; pattern values
// are compared literally. This keeps "get deployments.apps" from matching a
// secrets pattern, and keeps "verbs=[*] resources=[pods]" from being labeled
// cluster-admin.
func matchesRiskyPattern(rule rbacv1.PolicyRule, pattern RiskyPattern) bool {
	return ruleCoversAny(rule.Verbs, pattern.Verbs, false) &&
		ruleCoversAny(rule.APIGroups, pattern.APIGroups, false) &&
		ruleCoversAny(rule.Resources, pattern.Resources, true)
}

// ruleCoversAny reports whether any rule value grants any pattern value.
// A rule value covers a pattern value when they are equal or when the rule
// value is "*". With resourceSemantics, a rule value of "*/sub" additionally
// covers any pattern value of the form "resource/sub", mirroring the
// Kubernetes RBAC evaluator.
func ruleCoversAny(ruleVals, patternVals []string, resourceSemantics bool) bool {
	for _, p := range patternVals {
		for _, r := range ruleVals {
			if r == p || r == "*" {
				return true
			}
			if resourceSemantics && strings.HasPrefix(r, "*/") {
				if idx := strings.Index(p, "/"); idx != -1 && p[idx+1:] == r[2:] {
					return true
				}
			}
		}
	}
	return false
}

// PrintRiskyPermissions outputs risky permissions analysis. resolveErrs are
// failures that occurred while gathering the subject's permissions; when
// non-empty the analysis is incomplete and is reported as such rather than as
// a clean bill of health.
func PrintRiskyPermissions(w io.Writer, risks []rbac.RiskyPermission, resolveErrs []error) {
	if len(resolveErrs) > 0 {
		_, _ = fmt.Fprintf(w, "WARNING: analysis is INCOMPLETE, %d RBAC object(s) could not be read:\n", len(resolveErrs))
		for _, e := range resolveErrs {
			_, _ = fmt.Fprintf(w, "  - %v\n", e)
		}
		_, _ = fmt.Fprintln(w)
	}

	if len(risks) == 0 {
		if len(resolveErrs) > 0 {
			_, _ = fmt.Fprintln(w, "No risky permissions detected in the readable RBAC objects (result incomplete).")
		} else {
			_, _ = fmt.Fprintln(w, "No risky permissions detected.")
		}
		return
	}

	_, _ = fmt.Fprintf(w, "Found %d risky permission pattern(s):\n\n", len(risks))

	// Group by severity
	critical := filterBySeverity(risks, "critical")
	high := filterBySeverity(risks, "high")
	medium := filterBySeverity(risks, "medium")

	if len(critical) > 0 {
		_, _ = fmt.Fprintln(w, "CRITICAL:")
		for _, risk := range critical {
			printRisk(w, risk)
		}
	}

	if len(high) > 0 {
		_, _ = fmt.Fprintln(w, "HIGH:")
		for _, risk := range high {
			printRisk(w, risk)
		}
	}

	if len(medium) > 0 {
		_, _ = fmt.Fprintln(w, "MEDIUM:")
		for _, risk := range medium {
			printRisk(w, risk)
		}
	}
}

func filterBySeverity(risks []rbac.RiskyPermission, severity string) []rbac.RiskyPermission {
	var filtered []rbac.RiskyPermission
	for _, r := range risks {
		if r.Severity == severity {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

func printRisk(w io.Writer, risk rbac.RiskyPermission) {
	_, _ = fmt.Fprintf(w, "  - %s\n", risk.Category)
	_, _ = fmt.Fprintf(w, "    %s\n", risk.Description)
	_, _ = fmt.Fprintf(w, "    Granted via:\n")
	for _, grant := range risk.Grants {
		_, _ = fmt.Fprintf(w, "      - %s/%s -> %s/%s\n",
			grant.Binding.Kind, grant.Binding.Name,
			grant.Role.Kind, grant.Role.Name)
	}
	_, _ = fmt.Fprintln(w)
}
