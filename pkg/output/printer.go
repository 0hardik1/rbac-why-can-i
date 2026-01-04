package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/hardik/kubectl-rbac-why/pkg/rbac"
)

// ContextInfo holds information about the current kubeconfig context
// Used when --as is not provided to show where the subject came from
type ContextInfo struct {
	ContextName string
	ClusterName string
	AuthInfo    string   // The kubeconfig authInfo name
	UserName    string   // The actual user identity (e.g., CN from cert)
	Groups      []string // Groups the user belongs to (e.g., O from cert)
	Namespace   string
	AuthMethod  string // e.g., "client-certificate", "token", "exec", etc.
}

// Printer interface for different output formats
type Printer interface {
	Print(w io.Writer, result *rbac.PermissionResult, ctx *ContextInfo) error
}

// NewPrinter creates a printer based on the output format
func NewPrinter(format string) (Printer, error) {
	switch format {
	case "text", "":
		return &TextPrinter{}, nil
	case "json":
		return &JSONPrinter{}, nil
	case "yaml":
		return &YAMLPrinter{}, nil
	case "dot":
		return &DotPrinter{}, nil
	case "mermaid":
		return &MermaidPrinter{}, nil
	default:
		return nil, fmt.Errorf("unknown output format: %s", format)
	}
}

// TextPrinter outputs human-readable text
type TextPrinter struct{}

func (p *TextPrinter) Print(w io.Writer, result *rbac.PermissionResult, ctx *ContextInfo) error {
	// If using current context (--as not provided), show context info first
	if ctx != nil {
		_, _ = fmt.Fprintf(w, "Using current context:\n")
		_, _ = fmt.Fprintf(w, "  Context:    %s\n", ctx.ContextName)
		_, _ = fmt.Fprintf(w, "  Cluster:    %s\n", ctx.ClusterName)
		_, _ = fmt.Fprintf(w, "  AuthInfo:   %s\n", ctx.AuthInfo)
		_, _ = fmt.Fprintf(w, "  User:       %s\n", ctx.UserName)
		if len(ctx.Groups) > 0 {
			_, _ = fmt.Fprintf(w, "  Groups:     %s\n", strings.Join(ctx.Groups, ", "))
		}
		if ctx.AuthMethod != "" {
			_, _ = fmt.Fprintf(w, "  AuthMethod: %s\n", ctx.AuthMethod)
		}
		if ctx.Namespace != "" {
			_, _ = fmt.Fprintf(w, "  Namespace:  %s\n", ctx.Namespace)
		}
		_, _ = fmt.Fprintln(w)
	}

	if !result.Allowed {
		_, _ = fmt.Fprintf(w, "DENIED: No RBAC rules grant %s %s to %s\n",
			result.Request.Verb,
			formatResource(result.Request),
			result.Subject.String())
		if result.Request.Namespace != "" {
			_, _ = fmt.Fprintf(w, "Namespace: %s\n", result.Request.Namespace)
		}
		return nil
	}

	_, _ = fmt.Fprintf(w, "ALLOWED: %s can %s %s",
		result.Subject.String(),
		result.Request.Verb,
		formatResource(result.Request))
	if result.Request.Namespace != "" {
		_, _ = fmt.Fprintf(w, " in namespace %s", result.Request.Namespace)
	}
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w)

	_, _ = fmt.Fprintf(w, "Permission granted through %d path(s):\n\n", len(result.Grants))

	for i, grant := range result.Grants {
		_, _ = fmt.Fprintf(w, "Path %d:\n", i+1)
		_, _ = fmt.Fprintf(w, "  Subject: %s\n", result.Subject.String())
		_, _ = fmt.Fprintf(w, "      |\n")
		_, _ = fmt.Fprintf(w, "      v\n")
		_, _ = fmt.Fprintf(w, "  %s: %s", grant.Binding.Kind, grant.Binding.Name)
		if grant.Binding.Namespace != "" {
			_, _ = fmt.Fprintf(w, " (namespace: %s)", grant.Binding.Namespace)
		}
		_, _ = fmt.Fprintf(w, "\n")
		_, _ = fmt.Fprintf(w, "      |\n")
		_, _ = fmt.Fprintf(w, "      v\n")
		_, _ = fmt.Fprintf(w, "  %s: %s", grant.Role.Kind, grant.Role.Name)
		if grant.Role.Namespace != "" {
			_, _ = fmt.Fprintf(w, " (namespace: %s)", grant.Role.Namespace)
		}
		_, _ = fmt.Fprintf(w, "\n")
		_, _ = fmt.Fprintf(w, "      |\n")
		_, _ = fmt.Fprintf(w, "      v\n")
		_, _ = fmt.Fprintf(w, "  Rule: %s\n", formatRule(grant.MatchingRule))
		_, _ = fmt.Fprintf(w, "  Scope: %s\n\n", grant.Scope)
	}

	return nil
}

func formatResource(request rbac.PermissionRequest) string {
	resource := request.Resource
	if request.Subresource != "" {
		resource = resource + "/" + request.Subresource
	}
	if request.APIGroup != "" {
		resource = resource + "." + request.APIGroup
	}
	if request.ResourceName != "" {
		resource = resource + " (name: " + request.ResourceName + ")"
	}
	return resource
}

func formatRule(rule rbacv1.PolicyRule) string {
	var parts []string

	if len(rule.APIGroups) > 0 {
		if len(rule.APIGroups) == 1 && rule.APIGroups[0] == "" {
			parts = append(parts, "apiGroups=[\"\"]")
		} else {
			parts = append(parts, fmt.Sprintf("apiGroups=%v", rule.APIGroups))
		}
	}
	if len(rule.Resources) > 0 {
		parts = append(parts, fmt.Sprintf("resources=%v", rule.Resources))
	}
	if len(rule.Verbs) > 0 {
		parts = append(parts, fmt.Sprintf("verbs=%v", rule.Verbs))
	}
	if len(rule.ResourceNames) > 0 {
		parts = append(parts, fmt.Sprintf("resourceNames=%v", rule.ResourceNames))
	}

	return strings.Join(parts, ", ")
}

// ContextOutput is the structure for context info in JSON/YAML output
type ContextOutput struct {
	ContextName string   `json:"contextName"`
	ClusterName string   `json:"clusterName"`
	AuthInfo    string   `json:"authInfo"`
	UserName    string   `json:"userName"`
	Groups      []string `json:"groups,omitempty"`
	AuthMethod  string   `json:"authMethod,omitempty"`
	Namespace   string   `json:"namespace,omitempty"`
}

// JSONOutput is the structure for JSON output
type JSONOutput struct {
	Context *ContextOutput `json:"context,omitempty"`
	Allowed bool           `json:"allowed"`
	Subject SubjectOutput  `json:"subject"`
	Request RequestOutput  `json:"request"`
	Grants  []GrantOutput  `json:"grants,omitempty"`
	Errors  []string       `json:"errors,omitempty"`
}

type SubjectOutput struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

type RequestOutput struct {
	Verb         string `json:"verb"`
	APIGroup     string `json:"apiGroup"`
	Resource     string `json:"resource"`
	Subresource  string `json:"subresource,omitempty"`
	ResourceName string `json:"resourceName,omitempty"`
	Namespace    string `json:"namespace,omitempty"`
}

type GrantOutput struct {
	Binding      BindingOutput `json:"binding"`
	Role         RoleOutput    `json:"role"`
	MatchingRule RuleOutput    `json:"matchingRule"`
	Scope        string        `json:"scope"`
}

type BindingOutput struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

type RoleOutput struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

type RuleOutput struct {
	Verbs         []string `json:"verbs"`
	APIGroups     []string `json:"apiGroups"`
	Resources     []string `json:"resources"`
	ResourceNames []string `json:"resourceNames,omitempty"`
}

// JSONPrinter outputs JSON format
type JSONPrinter struct{}

func (p *JSONPrinter) Print(w io.Writer, result *rbac.PermissionResult, ctx *ContextInfo) error {
	output := JSONOutput{
		Allowed: result.Allowed,
		Subject: SubjectOutput{
			Kind:      result.Subject.Kind,
			Name:      result.Subject.Name,
			Namespace: result.Subject.Namespace,
		},
		Request: RequestOutput{
			Verb:         result.Request.Verb,
			APIGroup:     result.Request.APIGroup,
			Resource:     result.Request.Resource,
			Subresource:  result.Request.Subresource,
			ResourceName: result.Request.ResourceName,
			Namespace:    result.Request.Namespace,
		},
		Grants: make([]GrantOutput, 0, len(result.Grants)),
	}

	// Include context info if --as was not provided
	if ctx != nil {
		output.Context = &ContextOutput{
			ContextName: ctx.ContextName,
			ClusterName: ctx.ClusterName,
			AuthInfo:    ctx.AuthInfo,
			UserName:    ctx.UserName,
			Groups:      ctx.Groups,
			AuthMethod:  ctx.AuthMethod,
			Namespace:   ctx.Namespace,
		}
	}

	for _, grant := range result.Grants {
		grantOutput := GrantOutput{
			Binding: BindingOutput{
				Kind:      grant.Binding.Kind,
				Name:      grant.Binding.Name,
				Namespace: grant.Binding.Namespace,
			},
			Role: RoleOutput{
				Kind:      grant.Role.Kind,
				Name:      grant.Role.Name,
				Namespace: grant.Role.Namespace,
			},
			MatchingRule: RuleOutput{
				Verbs:         grant.MatchingRule.Verbs,
				APIGroups:     grant.MatchingRule.APIGroups,
				Resources:     grant.MatchingRule.Resources,
				ResourceNames: grant.MatchingRule.ResourceNames,
			},
			Scope: string(grant.Scope),
		}
		output.Grants = append(output.Grants, grantOutput)
	}

	for _, err := range result.Errors {
		output.Errors = append(output.Errors, err.Error())
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

// YAMLPrinter outputs YAML format
type YAMLPrinter struct{}

func (p *YAMLPrinter) Print(w io.Writer, result *rbac.PermissionResult, ctx *ContextInfo) error {
	output := JSONOutput{
		Allowed: result.Allowed,
		Subject: SubjectOutput{
			Kind:      result.Subject.Kind,
			Name:      result.Subject.Name,
			Namespace: result.Subject.Namespace,
		},
		Request: RequestOutput{
			Verb:         result.Request.Verb,
			APIGroup:     result.Request.APIGroup,
			Resource:     result.Request.Resource,
			Subresource:  result.Request.Subresource,
			ResourceName: result.Request.ResourceName,
			Namespace:    result.Request.Namespace,
		},
		Grants: make([]GrantOutput, 0, len(result.Grants)),
	}

	// Include context info if --as was not provided
	if ctx != nil {
		output.Context = &ContextOutput{
			ContextName: ctx.ContextName,
			ClusterName: ctx.ClusterName,
			AuthInfo:    ctx.AuthInfo,
			UserName:    ctx.UserName,
			Groups:      ctx.Groups,
			AuthMethod:  ctx.AuthMethod,
			Namespace:   ctx.Namespace,
		}
	}

	for _, grant := range result.Grants {
		grantOutput := GrantOutput{
			Binding: BindingOutput{
				Kind:      grant.Binding.Kind,
				Name:      grant.Binding.Name,
				Namespace: grant.Binding.Namespace,
			},
			Role: RoleOutput{
				Kind:      grant.Role.Kind,
				Name:      grant.Role.Name,
				Namespace: grant.Role.Namespace,
			},
			MatchingRule: RuleOutput{
				Verbs:         grant.MatchingRule.Verbs,
				APIGroups:     grant.MatchingRule.APIGroups,
				Resources:     grant.MatchingRule.Resources,
				ResourceNames: grant.MatchingRule.ResourceNames,
			},
			Scope: string(grant.Scope),
		}
		output.Grants = append(output.Grants, grantOutput)
	}

	for _, err := range result.Errors {
		output.Errors = append(output.Errors, err.Error())
	}

	encoder := yaml.NewEncoder(w)
	encoder.SetIndent(2)
	return encoder.Encode(output)
}
