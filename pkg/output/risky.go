package output

import (
	"fmt"
	"io"

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

// RiskyPatterns contains known dangerous permission patterns
var RiskyPatterns = []RiskyPattern{
	{
		Category:    "secrets-access",
		Severity:    "critical",
		Description: "Access to Secrets can expose sensitive credentials, tokens, and keys",
		Verbs:       []string{"get", "list", "watch", "*"},
		APIGroups:   []string{"", "*"},
		Resources:   []string{"secrets", "*"},
	},
	{
		Category:    "pod-exec",
		Severity:    "critical",
		Description: "Pod exec allows arbitrary command execution in containers",
		Verbs:       []string{"create", "*"},
		APIGroups:   []string{"", "*"},
		Resources:   []string{"pods/exec", "*"},
	},
	{
		Category:    "pod-attach",
		Severity:    "critical",
		Description: "Pod attach allows connecting to running containers",
		Verbs:       []string{"create", "*"},
		APIGroups:   []string{"", "*"},
		Resources:   []string{"pods/attach", "*"},
	},
	{
		Category:    "pod-create",
		Severity:    "high",
		Description: "Pod creation can lead to privilege escalation via hostPath, hostPID, etc.",
		Verbs:       []string{"create", "*"},
		APIGroups:   []string{"", "*"},
		Resources:   []string{"pods", "*"},
	},
	{
		Category:    "impersonate",
		Severity:    "critical",
		Description: "Impersonation allows assuming other user/group identities",
		Verbs:       []string{"impersonate", "*"},
		APIGroups:   []string{"", "*"},
		Resources:   []string{"users", "groups", "serviceaccounts", "*"},
	},
	{
		Category:    "nodes-proxy",
		Severity:    "critical",
		Description: "Node proxy access can execute commands on nodes via kubelet API",
		Verbs:       []string{"get", "create", "*"},
		APIGroups:   []string{"", "*"},
		Resources:   []string{"nodes/proxy", "*"},
	},
	{
		Category:    "persistent-volume-create",
		Severity:    "high",
		Description: "PV creation with hostPath can access node filesystem",
		Verbs:       []string{"create", "*"},
		APIGroups:   []string{"", "*"},
		Resources:   []string{"persistentvolumes", "*"},
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
		Verbs:       []string{"create", "update", "patch", "*"},
		APIGroups:   []string{"rbac.authorization.k8s.io", "*"},
		Resources:   []string{"roles", "clusterroles", "*"},
	},
	{
		Category:    "binding-escalation",
		Severity:    "critical",
		Description: "Ability to create/modify bindings can grant any permissions",
		Verbs:       []string{"create", "update", "patch", "*"},
		APIGroups:   []string{"rbac.authorization.k8s.io", "*"},
		Resources:   []string{"rolebindings", "clusterrolebindings", "*"},
	},
	{
		Category:    "csr-approve",
		Severity:    "high",
		Description: "CSR approval can issue certificates for any identity",
		Verbs:       []string{"approve", "*"},
		APIGroups:   []string{"certificates.k8s.io", "*"},
		Resources:   []string{"certificatesigningrequests/approval", "*"},
	},
	{
		Category:    "token-request",
		Severity:    "high",
		Description: "Token request can generate tokens for any service account",
		Verbs:       []string{"create", "*"},
		APIGroups:   []string{"", "*"},
		Resources:   []string{"serviceaccounts/token", "*"},
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

func matchesRiskyPattern(rule rbacv1.PolicyRule, pattern RiskyPattern) bool {
	verbMatch := false
	for _, pv := range pattern.Verbs {
		for _, rv := range rule.Verbs {
			if rv == pv || rv == "*" {
				verbMatch = true
				break
			}
		}
		if verbMatch {
			break
		}
	}
	if !verbMatch {
		return false
	}

	groupMatch := false
	for _, pg := range pattern.APIGroups {
		for _, rg := range rule.APIGroups {
			if rg == pg || rg == "*" || pg == "*" {
				groupMatch = true
				break
			}
		}
		if groupMatch {
			break
		}
	}
	if !groupMatch {
		return false
	}

	resourceMatch := false
	for _, pr := range pattern.Resources {
		for _, rr := range rule.Resources {
			if rr == pr || rr == "*" || pr == "*" {
				resourceMatch = true
				break
			}
		}
		if resourceMatch {
			break
		}
	}

	return resourceMatch
}

// PrintRiskyPermissions outputs risky permissions analysis
func PrintRiskyPermissions(w io.Writer, risks []rbac.RiskyPermission) {
	if len(risks) == 0 {
		_, _ = fmt.Fprintln(w, "No risky permissions detected.")
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
