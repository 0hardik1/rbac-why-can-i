package cani

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	"github.com/hardik/kubectl-rbac-why/pkg/client"
	"github.com/hardik/kubectl-rbac-why/pkg/output"
	"github.com/hardik/kubectl-rbac-why/pkg/rbac"
)

var (
	longDesc = `Explains why a permission is granted in Kubernetes RBAC.

Shows the exact Role/ClusterRole and Binding chain that grants
a permission to a subject. This helps answer the question:
"WHY can this service account do X?"

Unlike 'kubectl auth can-i', this tool doesn't just tell you
yes/no, it shows you the complete RBAC chain that grants
the permission.`

	examples = `  # Check why a service account can get secrets
  kubectl rbac-why can-i --as system:serviceaccount:default:my-sa get secrets -n default

  # Check cluster-wide permissions for listing nodes
  kubectl rbac-why can-i --as system:serviceaccount:kube-system:admin list nodes

  # Check pod exec permissions
  kubectl rbac-why can-i --as system:serviceaccount:default:debug-sa create pods/exec -n default

  # Output as JSON for programmatic use
  kubectl rbac-why can-i --as system:serviceaccount:default:my-sa get pods -o json

  # Generate a DOT graph
  kubectl rbac-why can-i --as system:serviceaccount:default:my-sa get pods -o dot | dot -Tpng > rbac.png

  # Generate a Mermaid diagram
  kubectl rbac-why can-i --as system:serviceaccount:default:my-sa get pods -o mermaid

  # Show risky permissions for a subject
  kubectl rbac-why can-i --as system:serviceaccount:default:my-sa --show-risky -n default`
)

// NewCmdRbacWhy creates the rbac-why root command
func NewCmdRbacWhy(streams genericclioptions.IOStreams) *cobra.Command {
	o := NewRbacWhyOptions(streams)

	cmd := &cobra.Command{
		Use:     "rbac-why can-i --as SUBJECT VERB RESOURCE [flags]",
		Short:   "Explain why a permission is granted in RBAC",
		Long:    longDesc,
		Example: examples,
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Handle "can-i" subcommand or direct usage
			if len(args) > 0 && args[0] == "can-i" {
				args = args[1:]
			}

			if err := o.Complete(args); err != nil {
				return err
			}
			if err := o.Validate(); err != nil {
				return err
			}
			return o.Run(cmd.Context())
		},
	}

	// Add kubeconfig flags first (includes --as, --namespace, etc.)
	o.ConfigFlags.AddFlags(cmd.Flags())

	// Add our custom flags
	cmd.Flags().StringVarP(&o.Output, "output", "o", "text", "Output format: text, json, yaml, dot, mermaid")
	cmd.Flags().BoolVar(&o.ShowRisky, "show-risky", false, "Analyze and show risky permissions for the subject")

	return cmd
}

// Run executes the rbac-why command
func (o *RbacWhyOptions) Run(ctx context.Context) error {
	// Parse the subject
	subject, err := rbac.ParseSubject(o.As)
	if err != nil {
		return fmt.Errorf("failed to parse subject: %w", err)
	}

	// Create Kubernetes client WITHOUT impersonation
	// We need to read RBAC resources with the actual user's permissions,
	// not as the subject being checked
	savedImpersonate := o.ConfigFlags.Impersonate
	savedImpersonateGroup := o.ConfigFlags.ImpersonateGroup
	savedImpersonateUID := o.ConfigFlags.ImpersonateUID

	// Temporarily clear impersonation settings
	emptyString := ""
	o.ConfigFlags.Impersonate = &emptyString
	o.ConfigFlags.ImpersonateGroup = &[]string{}
	o.ConfigFlags.ImpersonateUID = &emptyString

	restConfig, err := o.ConfigFlags.ToRESTConfig()
	if err != nil {
		return fmt.Errorf("failed to create REST config: %w", err)
	}

	// Restore impersonation settings
	o.ConfigFlags.Impersonate = savedImpersonate
	o.ConfigFlags.ImpersonateGroup = savedImpersonateGroup
	o.ConfigFlags.ImpersonateUID = savedImpersonateUID

	rbacClient, err := client.NewK8sRBACClient(restConfig)
	if err != nil {
		return fmt.Errorf("failed to create RBAC client: %w", err)
	}

	resolver := rbac.NewResolver(rbacClient)

	// Handle --show-risky flag
	if o.ShowRisky {
		return o.runRiskyAnalysis(ctx, resolver, subject)
	}

	// Normal permission check
	request := o.ToPermissionRequest()
	result, err := resolver.ResolvePermission(ctx, subject, request)
	if err != nil {
		return fmt.Errorf("failed to resolve permission: %w", err)
	}

	// Print result
	printer, err := output.NewPrinter(o.Output)
	if err != nil {
		return err
	}

	return printer.Print(o.Out, result)
}

// runRiskyAnalysis shows risky permissions for a subject
func (o *RbacWhyOptions) runRiskyAnalysis(ctx context.Context, resolver *rbac.Resolver, subject rbac.Subject) error {
	grants, err := resolver.ResolveAllPermissions(ctx, subject, o.Namespace)
	if err != nil {
		return fmt.Errorf("failed to resolve permissions: %w", err)
	}

	risks := output.AnalyzeRiskyPermissions(grants)
	output.PrintRiskyPermissions(o.Out, risks)
	return nil
}
