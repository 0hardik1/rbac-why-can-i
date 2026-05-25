package output

import (
	"encoding/json"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"

	"github.com/hardik/kubectl-rbac-why/pkg/rbac"
)

// reverseOutput is the JSON/YAML structure for who-can results.
type reverseOutput struct {
	Request  RequestOutput          `json:"request"`
	Subjects []reverseSubjectOutput `json:"subjects"`
}

type reverseSubjectOutput struct {
	Kind      string        `json:"kind"`
	Name      string        `json:"name"`
	Namespace string        `json:"namespace,omitempty"`
	Grants    []GrantOutput `json:"grants"`
}

// PrintSubjectsWithPermission renders a reverse-lookup (who-can) result.
// Supported formats: text, json, yaml.
func PrintSubjectsWithPermission(w io.Writer, result *rbac.ReverseResult, format string) error {
	switch format {
	case "text", "":
		return printReverseText(w, result)
	case "json":
		return printReverseStructured(w, result, "json")
	case "yaml":
		return printReverseStructured(w, result, "yaml")
	default:
		return fmt.Errorf("--who-can supports output formats text, json, yaml (got %q)", format)
	}
}

func printReverseText(w io.Writer, result *rbac.ReverseResult) error {
	verb := result.Request.Verb
	res := formatResource(result.Request)

	scope := ""
	if result.Request.Namespace != "" {
		scope = " in namespace " + result.Request.Namespace
	}

	if len(result.Subjects) == 0 {
		_, _ = fmt.Fprintf(w, "No subjects can %s %s%s.\n", verb, res, scope)
		return nil
	}

	_, _ = fmt.Fprintf(w, "%d subject(s) can %s %s%s:\n\n", len(result.Subjects), verb, res, scope)
	for _, sg := range result.Subjects {
		_, _ = fmt.Fprintf(w, "- %s\n", sg.Subject.String())
		for _, g := range sg.Grants {
			binding := g.Binding.Kind + " " + g.Binding.Name
			if g.Binding.Namespace != "" {
				binding += " (ns: " + g.Binding.Namespace + ")"
			}
			role := g.Role.Kind + " " + g.Role.Name
			if g.Role.Namespace != "" {
				role += " (ns: " + g.Role.Namespace + ")"
			}
			_, _ = fmt.Fprintf(w, "    via %s -> %s [%s]\n", binding, role, g.Scope)
		}
	}
	return nil
}

func printReverseStructured(w io.Writer, result *rbac.ReverseResult, format string) error {
	out := reverseOutput{
		Request: RequestOutput{
			Verb:           result.Request.Verb,
			APIGroup:       result.Request.APIGroup,
			Resource:       result.Request.Resource,
			Subresource:    result.Request.Subresource,
			ResourceName:   result.Request.ResourceName,
			Namespace:      result.Request.Namespace,
			NonResourceURL: result.Request.NonResourceURL,
		},
		Subjects: make([]reverseSubjectOutput, 0, len(result.Subjects)),
	}

	for _, sg := range result.Subjects {
		so := reverseSubjectOutput{
			Kind:      sg.Subject.Kind,
			Name:      sg.Subject.Name,
			Namespace: sg.Subject.Namespace,
			Grants:    make([]GrantOutput, 0, len(sg.Grants)),
		}
		for _, g := range sg.Grants {
			so.Grants = append(so.Grants, GrantOutput{
				Binding:      BindingOutput{Kind: g.Binding.Kind, Name: g.Binding.Name, Namespace: g.Binding.Namespace},
				Role:         RoleOutput{Kind: g.Role.Kind, Name: g.Role.Name, Namespace: g.Role.Namespace},
				MatchingRule: ruleToOutput(g.MatchingRule),
				Scope:        string(g.Scope),
			})
		}
		out.Subjects = append(out.Subjects, so)
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
