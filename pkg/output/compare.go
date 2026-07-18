package output

import (
	"encoding/json"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"

	"github.com/hardik/kubectl-rbac-why/pkg/rbac"
)

type comparisonOutput struct {
	SubjectA subjectRef        `json:"subjectA"`
	SubjectB subjectRef        `json:"subjectB"`
	OnlyA    []ruleGrantOutput `json:"onlyA"`
	OnlyB    []ruleGrantOutput `json:"onlyB"`
	Shared   []ruleGrantOutput `json:"shared"`
}

type subjectRef struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

type ruleGrantOutput struct {
	Rule   RuleOutput    `json:"rule"`
	Grants []GrantOutput `json:"grants"`
}

// PrintComparison renders a two-subject permission comparison.
// Supported formats: text, json, yaml.
func PrintComparison(w io.Writer, comp *rbac.PermissionComparison, format string) error {
	switch format {
	case "text", "":
		return printComparisonText(w, comp)
	case "json":
		return printComparisonStructured(w, comp, "json")
	case "yaml":
		return printComparisonStructured(w, comp, "yaml")
	default:
		return fmt.Errorf("--compare-with supports output formats text, json, yaml (got %q)", format)
	}
}

func printComparisonText(w io.Writer, comp *rbac.PermissionComparison) error {
	_, _ = fmt.Fprintln(w, "Comparing effective permissions:")
	_, _ = fmt.Fprintf(w, "  A: %s\n", comp.SubjectA.String())
	_, _ = fmt.Fprintf(w, "  B: %s\n\n", comp.SubjectB.String())

	printSide := func(title string, rgs []rbac.RuleGrant) {
		_, _ = fmt.Fprintf(w, "%s (%d rule(s)):\n", title, len(rgs))
		if len(rgs) == 0 {
			_, _ = fmt.Fprintln(w, "  (none)")
		}
		for _, rg := range rgs {
			_, _ = fmt.Fprintf(w, "  - %s\n", formatRule(rg.Rule))
			for _, g := range rg.Grants {
				_, _ = fmt.Fprintf(w, "      via %s %s -> %s %s [%s]\n",
					g.Binding.Kind, g.Binding.Name, g.Role.Kind, g.Role.Name, g.Scope)
			}
		}
		_, _ = fmt.Fprintln(w)
	}

	printSide("Only A can", comp.OnlyA)
	printSide("Only B can", comp.OnlyB)
	_, _ = fmt.Fprintf(w, "Shared: %d rule(s)\n", len(comp.Shared))
	return nil
}

func printComparisonStructured(w io.Writer, comp *rbac.PermissionComparison, format string) error {
	out := comparisonOutput{
		SubjectA: subjectRef{Kind: comp.SubjectA.Kind, Name: comp.SubjectA.Name, Namespace: comp.SubjectA.Namespace},
		SubjectB: subjectRef{Kind: comp.SubjectB.Kind, Name: comp.SubjectB.Name, Namespace: comp.SubjectB.Namespace},
		OnlyA:    ruleGrantsToOutput(comp.OnlyA),
		OnlyB:    ruleGrantsToOutput(comp.OnlyB),
		Shared:   ruleGrantsToOutput(comp.Shared),
	}

	if format == "yaml" {
		encoder := yaml.NewEncoder(w)
		encoder.SetIndent(2)
		return encoder.Encode(out)
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(out)
}

func ruleGrantsToOutput(rgs []rbac.RuleGrant) []ruleGrantOutput {
	out := make([]ruleGrantOutput, 0, len(rgs))
	for _, rg := range rgs {
		ro := ruleGrantOutput{
			Rule:   ruleToOutput(rg.Rule),
			Grants: make([]GrantOutput, 0, len(rg.Grants)),
		}
		for _, g := range rg.Grants {
			ro.Grants = append(ro.Grants, GrantOutput{
				Binding:      BindingOutput{Kind: g.Binding.Kind, Name: g.Binding.Name, Namespace: g.Binding.Namespace},
				Role:         RoleOutput{Kind: g.Role.Kind, Name: g.Role.Name, Namespace: g.Role.Namespace},
				MatchingRule: ruleToOutput(g.MatchingRule),
				Scope:        string(g.Scope),
			})
		}
		out = append(out, ro)
	}
	return out
}
