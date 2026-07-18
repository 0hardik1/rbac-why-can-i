package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/yaml"

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

	// EKS-specific informational fields. All optional and zero by default.
	EKSClusterName     string
	AccessPolicies     []AccessPolicyInfo // EKS-managed access policies attached to the principal's Access Entry
	PodIdentityForRole *PodIdentityInfo   // when the IAM role mapped to a SA via Pod Identity
	PodIdentityForSA   []PodIdentityInfo  // any Pod Identity associations bound to this SA
}

// AccessPolicyInfo describes an EKS-managed access policy attached to an
// Access Entry. These policies grant Kubernetes permissions out-of-band of
// the standard (Cluster)RoleBinding chain.
type AccessPolicyInfo struct {
	PolicyARN  string   `json:"policyArn"`
	ScopeType  string   `json:"scopeType"`            // "cluster" or "namespace"
	Namespaces []string `json:"namespaces,omitempty"` // populated when ScopeType is "namespace"
}

// PodIdentityInfo describes an EKS Pod Identity Association.
type PodIdentityInfo struct {
	AssociationID  string `json:"associationId"`
	Namespace      string `json:"namespace"`
	ServiceAccount string `json:"serviceAccount"`
	RoleARN        string `json:"roleArn"`
}

// Printer interface for different output formats
type Printer interface {
	Print(w io.Writer, result *rbac.PermissionResult, ctx *ContextInfo) error
}

// NewPrinter creates a printer based on the output format. color enables ANSI
// coloring for the text printer (ignored by other formats).
func NewPrinter(format string, color bool) (Printer, error) {
	switch format {
	case "text", "":
		return &TextPrinter{Color: color}, nil
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

// TextPrinter outputs human-readable text. Color enables ANSI coloring of the
// ALLOWED/DENIED verdict.
type TextPrinter struct {
	Color bool
}

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
		writeAWSIdentityContext(w, ctx)
	}

	if result.Incomplete() {
		_, _ = fmt.Fprintf(w, "%s: resolution is incomplete, %d RBAC object(s) could not be read:\n",
			colorize(p.Color, colorYellow, "WARNING"), len(result.Errors))
		for _, e := range result.Errors {
			_, _ = fmt.Fprintf(w, "  - %v\n", e)
		}
		_, _ = fmt.Fprintln(w)
	}

	if !result.Allowed {
		if result.Incomplete() {
			_, _ = fmt.Fprintf(w, "%s: no readable RBAC rule grants %s %s to %s, but not all RBAC objects could be read; this is NOT a definitive denial\n",
				colorize(p.Color, colorYellow, "INCOMPLETE"),
				result.Request.Verb,
				formatResource(result.Request),
				result.Subject.String())
		} else {
			_, _ = fmt.Fprintf(w, "%s: No RBAC rules grant %s %s to %s\n",
				colorize(p.Color, colorRed, "DENIED"),
				result.Request.Verb,
				formatResource(result.Request),
				result.Subject.String())
		}
		if result.Request.Namespace != "" {
			_, _ = fmt.Fprintf(w, "Namespace: %s\n", result.Request.Namespace)
		}
		return nil
	}

	_, _ = fmt.Fprintf(w, "%s: %s can %s %s",
		colorize(p.Color, colorGreen, "ALLOWED"),
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
	if request.NonResourceURL != "" {
		return request.NonResourceURL
	}
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
	if len(rule.NonResourceURLs) > 0 {
		parts = append(parts, fmt.Sprintf("nonResourceURLs=%v", rule.NonResourceURLs))
	}

	return strings.Join(parts, ", ")
}

// ruleToOutput converts a PolicyRule into its JSON/YAML output form.
func ruleToOutput(rule rbacv1.PolicyRule) RuleOutput {
	return RuleOutput{
		Verbs:           rule.Verbs,
		APIGroups:       rule.APIGroups,
		Resources:       rule.Resources,
		ResourceNames:   rule.ResourceNames,
		NonResourceURLs: rule.NonResourceURLs,
	}
}

// ContextOutput is the structure for context info in JSON/YAML output
type ContextOutput struct {
	ContextName        string             `json:"contextName"`
	ClusterName        string             `json:"clusterName"`
	AuthInfo           string             `json:"authInfo"`
	UserName           string             `json:"userName"`
	Groups             []string           `json:"groups,omitempty"`
	AuthMethod         string             `json:"authMethod,omitempty"`
	Namespace          string             `json:"namespace,omitempty"`
	EKSClusterName     string             `json:"eksClusterName,omitempty"`
	AccessPolicies     []AccessPolicyInfo `json:"accessPolicies,omitempty"`
	PodIdentityForRole *PodIdentityInfo   `json:"podIdentityForRole,omitempty"`
	PodIdentityForSA   []PodIdentityInfo  `json:"podIdentityForServiceAccount,omitempty"`
}

// contextOutputFromInfo copies the public fields from ContextInfo into the
// JSON-serialisable ContextOutput. The AuthInfo-side fields are preserved
// by value (slices not deep-copied).
func contextOutputFromInfo(ctx *ContextInfo) *ContextOutput {
	if ctx == nil {
		return nil
	}
	return &ContextOutput{
		ContextName:        ctx.ContextName,
		ClusterName:        ctx.ClusterName,
		AuthInfo:           ctx.AuthInfo,
		UserName:           ctx.UserName,
		Groups:             ctx.Groups,
		AuthMethod:         ctx.AuthMethod,
		Namespace:          ctx.Namespace,
		EKSClusterName:     ctx.EKSClusterName,
		AccessPolicies:     ctx.AccessPolicies,
		PodIdentityForRole: ctx.PodIdentityForRole,
		PodIdentityForSA:   ctx.PodIdentityForSA,
	}
}

// writeAWSIdentityComments renders the EKS context as comment lines for
// graph formats (DOT, Mermaid). prefix is the format-specific comment
// marker, e.g. "  // " for DOT or "%% " for Mermaid. No-op when no EKS
// fields are populated.
func writeAWSIdentityComments(w io.Writer, ctx *ContextInfo, prefix string) {
	if ctx == nil {
		return
	}
	if ctx.EKSClusterName != "" {
		_, _ = fmt.Fprintf(w, "%sEKS Cluster: %s\n", prefix, ctx.EKSClusterName)
	}
	if ctx.PodIdentityForRole != nil {
		p := ctx.PodIdentityForRole
		_, _ = fmt.Fprintf(w, "%sPod Identity (role -> SA): %s/%s\n", prefix, p.Namespace, p.ServiceAccount)
	}
	for _, ap := range ctx.AccessPolicies {
		_, _ = fmt.Fprintf(w, "%sAccess Policy: %s (scope=%s)\n", prefix, ap.PolicyARN, ap.ScopeType)
	}
	for _, p := range ctx.PodIdentityForSA {
		_, _ = fmt.Fprintf(w, "%sPod Identity (SA -> role): %s\n", prefix, p.RoleARN)
	}
}

// writeAWSIdentityContext renders the EKS-specific informational block
// after the standard context block in text output. No-op if no EKS fields
// are populated.
func writeAWSIdentityContext(w io.Writer, ctx *ContextInfo) {
	if ctx == nil {
		return
	}
	hasEKS := ctx.EKSClusterName != "" ||
		len(ctx.AccessPolicies) > 0 ||
		ctx.PodIdentityForRole != nil ||
		len(ctx.PodIdentityForSA) > 0
	if !hasEKS {
		return
	}
	_, _ = fmt.Fprintln(w, "AWS / EKS identity:")
	if ctx.EKSClusterName != "" {
		_, _ = fmt.Fprintf(w, "  EKS Cluster: %s\n", ctx.EKSClusterName)
	}
	if ctx.PodIdentityForRole != nil {
		p := ctx.PodIdentityForRole
		_, _ = fmt.Fprintf(w, "  Pod Identity (IAM role -> ServiceAccount): %s/%s (associationId=%s)\n",
			p.Namespace, p.ServiceAccount, p.AssociationID)
	}
	if len(ctx.AccessPolicies) > 0 {
		_, _ = fmt.Fprintln(w, "  EKS-managed access policies (granted out-of-band by EKS, not part of RBAC walker):")
		for _, ap := range ctx.AccessPolicies {
			scope := ap.ScopeType
			if scope == "namespace" && len(ap.Namespaces) > 0 {
				scope = "namespace=[" + strings.Join(ap.Namespaces, ",") + "]"
			}
			_, _ = fmt.Fprintf(w, "    - %s (scope: %s)\n", ap.PolicyARN, scope)
		}
	}
	if len(ctx.PodIdentityForSA) > 0 {
		_, _ = fmt.Fprintln(w, "  Pod Identity associations for this ServiceAccount:")
		for _, p := range ctx.PodIdentityForSA {
			_, _ = fmt.Fprintf(w, "    - role: %s (associationId=%s)\n", p.RoleARN, p.AssociationID)
		}
	}
	_, _ = fmt.Fprintln(w)
}

// JSONOutput is the structure for JSON and YAML output
type JSONOutput struct {
	Context *ContextOutput `json:"context,omitempty"`
	Allowed bool           `json:"allowed"`
	// Incomplete is true when some RBAC objects could not be read; grants may
	// be missing and allowed=false is not a definitive denial.
	Incomplete bool          `json:"incomplete,omitempty"`
	Subject    SubjectOutput `json:"subject"`
	Request    RequestOutput `json:"request"`
	Grants     []GrantOutput `json:"grants,omitempty"`
	Errors     []string      `json:"errors,omitempty"`
}

type SubjectOutput struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

type RequestOutput struct {
	Verb           string `json:"verb"`
	APIGroup       string `json:"apiGroup"`
	Resource       string `json:"resource"`
	Subresource    string `json:"subresource,omitempty"`
	ResourceName   string `json:"resourceName,omitempty"`
	Namespace      string `json:"namespace,omitempty"`
	NonResourceURL string `json:"nonResourceURL,omitempty"`
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
	Verbs           []string `json:"verbs"`
	APIGroups       []string `json:"apiGroups"`
	Resources       []string `json:"resources"`
	ResourceNames   []string `json:"resourceNames,omitempty"`
	NonResourceURLs []string `json:"nonResourceURLs,omitempty"`
}

// buildStructuredOutput assembles the serialisable representation shared by
// the JSON and YAML printers.
func buildStructuredOutput(result *rbac.PermissionResult, ctx *ContextInfo) JSONOutput {
	output := JSONOutput{
		Allowed:    result.Allowed,
		Incomplete: result.Incomplete(),
		Subject: SubjectOutput{
			Kind:      result.Subject.Kind,
			Name:      result.Subject.Name,
			Namespace: result.Subject.Namespace,
		},
		Request: RequestOutput{
			Verb:           result.Request.Verb,
			APIGroup:       result.Request.APIGroup,
			Resource:       result.Request.Resource,
			Subresource:    result.Request.Subresource,
			ResourceName:   result.Request.ResourceName,
			Namespace:      result.Request.Namespace,
			NonResourceURL: result.Request.NonResourceURL,
		},
		Grants: make([]GrantOutput, 0, len(result.Grants)),
	}

	// Include context info if --as was not provided
	if ctx != nil {
		output.Context = contextOutputFromInfo(ctx)
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
			MatchingRule: ruleToOutput(grant.MatchingRule),
			Scope:        string(grant.Scope),
		}
		output.Grants = append(output.Grants, grantOutput)
	}

	for _, err := range result.Errors {
		output.Errors = append(output.Errors, err.Error())
	}

	return output
}

// JSONPrinter outputs JSON format
type JSONPrinter struct{}

func (p *JSONPrinter) Print(w io.Writer, result *rbac.PermissionResult, ctx *ContextInfo) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(buildStructuredOutput(result, ctx))
}

// YAMLPrinter outputs YAML format. It marshals via sigs.k8s.io/yaml so the
// json struct tags (field names and omitempty) apply to YAML exactly as
// documented for the JSON schema.
type YAMLPrinter struct{}

func (p *YAMLPrinter) Print(w io.Writer, result *rbac.PermissionResult, ctx *ContextInfo) error {
	data, err := yaml.Marshal(buildStructuredOutput(result, ctx))
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}
