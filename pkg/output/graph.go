package output

import (
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/hardik/kubectl-rbac-why/pkg/rbac"
)

// DotPrinter outputs GraphViz DOT format
type DotPrinter struct{}

func (p *DotPrinter) Print(w io.Writer, result *rbac.PermissionResult) error {
	_, _ = fmt.Fprintln(w, "digraph rbac {")
	_, _ = fmt.Fprintln(w, "  rankdir=LR;")
	_, _ = fmt.Fprintln(w, "  node [shape=box fontname=\"Helvetica\"];")
	_, _ = fmt.Fprintln(w, "  edge [fontname=\"Helvetica\" fontsize=10];")
	_, _ = fmt.Fprintln(w)

	if !result.Allowed {
		_, _ = fmt.Fprintf(w, "  denied [label=\"DENIED\\n%s cannot %s %s\" shape=octagon style=filled fillcolor=red fontcolor=white];\n",
			escapeLabel(result.Subject.String()),
			result.Request.Verb,
			result.Request.Resource)
		_, _ = fmt.Fprintln(w, "}")
		return nil
	}

	// Subject node
	subjectID := sanitizeID("subject")
	_, _ = fmt.Fprintf(w, "  %s [label=\"%s\" shape=ellipse style=filled fillcolor=lightblue];\n",
		subjectID, escapeLabel(result.Subject.String()))

	// Permission node
	permID := sanitizeID("permission")
	permLabel := fmt.Sprintf("%s %s", result.Request.Verb, result.Request.FullResource())
	_, _ = fmt.Fprintf(w, "  %s [label=\"%s\" shape=diamond style=filled fillcolor=lightgreen];\n",
		permID, escapeLabel(permLabel))

	for i, grant := range result.Grants {
		bindingID := fmt.Sprintf("binding_%d", i)
		roleID := fmt.Sprintf("role_%d", i)

		// Binding node
		bindingLabel := fmt.Sprintf("%s\\n%s", grant.Binding.Kind, grant.Binding.Name)
		if grant.Binding.Namespace != "" {
			bindingLabel += fmt.Sprintf("\\n(ns: %s)", grant.Binding.Namespace)
		}
		_, _ = fmt.Fprintf(w, "  %s [label=\"%s\" style=filled fillcolor=lightyellow];\n",
			bindingID, bindingLabel)

		// Role node
		roleLabel := fmt.Sprintf("%s\\n%s", grant.Role.Kind, grant.Role.Name)
		if grant.Role.Namespace != "" {
			roleLabel += fmt.Sprintf("\\n(ns: %s)", grant.Role.Namespace)
		}
		_, _ = fmt.Fprintf(w, "  %s [label=\"%s\" style=filled fillcolor=wheat];\n",
			roleID, roleLabel)

		// Edges
		_, _ = fmt.Fprintf(w, "  %s -> %s [label=\"binds\"];\n", subjectID, bindingID)
		_, _ = fmt.Fprintf(w, "  %s -> %s [label=\"refs\"];\n", bindingID, roleID)
		_, _ = fmt.Fprintf(w, "  %s -> %s [label=\"grants\"];\n", roleID, permID)
	}

	_, _ = fmt.Fprintln(w, "}")
	return nil
}

// MermaidPrinter outputs Mermaid diagram format
type MermaidPrinter struct{}

func (p *MermaidPrinter) Print(w io.Writer, result *rbac.PermissionResult) error {
	_, _ = fmt.Fprintln(w, "graph LR")

	if !result.Allowed {
		_, _ = fmt.Fprintf(w, "  denied{{DENIED: %s cannot %s %s}}\n",
			escapeMermaid(result.Subject.String()),
			result.Request.Verb,
			result.Request.Resource)
		_, _ = fmt.Fprintln(w, "  style denied fill:#f66,stroke:#333,color:#fff")
		return nil
	}

	// Subject node (stadium shape)
	subjectID := "subject"
	_, _ = fmt.Fprintf(w, "  %s([%s])\n", subjectID, escapeMermaid(result.Subject.String()))

	// Permission node (hexagon)
	permID := "permission"
	permLabel := fmt.Sprintf("%s %s", result.Request.Verb, result.Request.FullResource())
	_, _ = fmt.Fprintf(w, "  %s{{%s}}\n", permID, escapeMermaid(permLabel))

	for i, grant := range result.Grants {
		bindingID := fmt.Sprintf("binding%d", i)
		roleID := fmt.Sprintf("role%d", i)

		// Binding node
		bindingLabel := fmt.Sprintf("%s: %s", grant.Binding.Kind, grant.Binding.Name)
		if grant.Binding.Namespace != "" {
			bindingLabel += fmt.Sprintf(" ns:%s", grant.Binding.Namespace)
		}
		_, _ = fmt.Fprintf(w, "  %s[%s]\n", bindingID, escapeMermaid(bindingLabel))

		// Role node
		roleLabel := fmt.Sprintf("%s: %s", grant.Role.Kind, grant.Role.Name)
		if grant.Role.Namespace != "" {
			roleLabel += fmt.Sprintf(" ns:%s", grant.Role.Namespace)
		}
		_, _ = fmt.Fprintf(w, "  %s[%s]\n", roleID, escapeMermaid(roleLabel))

		// Edges
		_, _ = fmt.Fprintf(w, "  %s -->|binds| %s\n", subjectID, bindingID)
		_, _ = fmt.Fprintf(w, "  %s -->|refs| %s\n", bindingID, roleID)
		_, _ = fmt.Fprintf(w, "  %s -->|grants| %s\n", roleID, permID)
	}

	// Styling
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "  style subject fill:#add8e6,stroke:#333")
	_, _ = fmt.Fprintln(w, "  style permission fill:#90ee90,stroke:#333")
	for i := range result.Grants {
		_, _ = fmt.Fprintf(w, "  style binding%d fill:#fffacd,stroke:#333\n", i)
		_, _ = fmt.Fprintf(w, "  style role%d fill:#f5deb3,stroke:#333\n", i)
	}

	return nil
}

// sanitizeID makes a string safe for use as a DOT node ID
func sanitizeID(s string) string {
	reg := regexp.MustCompile(`[^a-zA-Z0-9_]`)
	return reg.ReplaceAllString(s, "_")
}

// escapeLabel escapes special characters for DOT labels
func escapeLabel(s string) string {
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	return s
}

// escapeMermaid escapes special characters for Mermaid
func escapeMermaid(s string) string {
	// Mermaid uses brackets for node shapes, so we need to escape them
	s = strings.ReplaceAll(s, "[", "(")
	s = strings.ReplaceAll(s, "]", ")")
	s = strings.ReplaceAll(s, "{", "(")
	s = strings.ReplaceAll(s, "}", ")")
	s = strings.ReplaceAll(s, "\"", "'")
	return s
}
