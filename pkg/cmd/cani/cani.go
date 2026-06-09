package cani

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/rest"

	"github.com/hardik/kubectl-rbac-why/pkg/client"
	"github.com/hardik/kubectl-rbac-why/pkg/output"
	"github.com/hardik/kubectl-rbac-why/pkg/rbac"
)

// eksClientFactory builds the EKS API client used by the orchestration
// chain. Overridable in tests.
var eksClientFactory = NewEKSClient

var (
	longDesc = `Explains why a permission is granted in Kubernetes RBAC.

Shows the exact Role/ClusterRole and Binding chain that grants
a permission to a subject. This helps answer the question:
"WHY can this user/service account do X?"

Unlike 'kubectl auth can-i', this tool doesn't just tell you
yes/no, it shows you the complete RBAC chain that grants
the permission.

If --as is not specified, the tool uses the current kubeconfig
context to determine the subject.`

	examples = `  # Check why the current user can get secrets (uses current kubeconfig context)
  kubectl rbac-why can-i get secrets -n default

  # Check why a specific service account can get secrets
  kubectl rbac-why can-i --as system:serviceaccount:default:my-sa get secrets -n default

  # Check cluster-wide permissions for listing nodes
  kubectl rbac-why can-i --as system:serviceaccount:kube-system:admin list nodes

  # Check pod exec permissions for current user
  kubectl rbac-why can-i create pods/exec -n default

  # Output as JSON for programmatic use
  kubectl rbac-why can-i get pods -o json

  # Generate a DOT graph
  kubectl rbac-why can-i get pods -o dot | dot -Tpng > rbac.png

  # Generate a Mermaid diagram
  kubectl rbac-why can-i get pods -o mermaid

  # Show risky permissions for a subject
  kubectl rbac-why can-i --as system:serviceaccount:default:my-sa --show-risky -n default

  # Show risky permissions for current user
  kubectl rbac-why can-i --show-risky -n default

  # Reverse lookup: list every subject that can delete secrets in a namespace
  kubectl rbac-why --who-can delete secrets -n default

  # Compare two subjects' effective permissions
  kubectl rbac-why --as system:serviceaccount:default:a --compare-with system:serviceaccount:default:b -n default`
)

// NewCmdRbacWhy creates the rbac-why root command
func NewCmdRbacWhy(streams genericclioptions.IOStreams) *cobra.Command {
	o := NewRbacWhyOptions(streams)

	cmd := &cobra.Command{
		Use:     "rbac-why can-i [--as SUBJECT] VERB RESOURCE [flags]",
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
	cmd.Flags().StringVar(&o.Color, "color", "auto", "Colorize text output: auto, always, never")
	cmd.Flags().BoolVar(&o.ShowRisky, "show-risky", false, "Analyze and show risky permissions for the subject")
	cmd.Flags().StringVarP(&o.AWSProfile, "profile", "p", "", "AWS profile to use for authentication (for EKS clusters)")
	cmd.Flags().StringVar(&o.ClusterName, "cluster-name", "", "EKS cluster name (overrides auto-detection from kubeconfig)")
	cmd.Flags().StringVar(&o.AWSRegion, "region", "", "AWS region for EKS API calls (overrides auto-detection)")
	cmd.Flags().BoolVar(&o.SkipEKS, "skip-eks-lookup", false, "Skip EKS Access Entries and Pod Identity lookups")
	cmd.Flags().BoolVar(&o.WhoCan, "who-can", false, "Reverse lookup: list all subjects that can perform VERB RESOURCE (ignores --as)")
	cmd.Flags().BoolVarP(&o.AllNamespaces, "all-namespaces", "A", false, "With --show-risky, scan RoleBindings across all namespaces")
	cmd.Flags().StringVar(&o.CompareWith, "compare-with", "", "Compare the subject's effective permissions with another subject (e.g. system:serviceaccount:ns:name)")

	return cmd
}

// Run executes the rbac-why command
func (o *RbacWhyOptions) Run(ctx context.Context) error {
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

	// Reverse lookup ("who can do X") resolves no subject identity and needs
	// no EKS handling; answer it directly with the RBAC client.
	if o.WhoCan {
		rbacClient, err := client.NewK8sRBACClient(restConfig)
		if err != nil {
			return fmt.Errorf("failed to create RBAC client: %w", err)
		}
		return o.runWhoCan(ctx, rbac.NewResolver(rbacClient))
	}

	// Build an EKS client once and reuse it for both identity resolution
	// and ServiceAccount enrichment. nil if EKS isn't applicable (no
	// cluster name, --skip-eks-lookup, or AWS config error).
	eksClient := o.maybeBuildEKSClient(ctx)

	// For AWS IAM auth, resolve the K8s identity by walking the priority
	// chain: Access Entry → aws-auth → Pod Identity → raw IAM ARN.
	if !o.AsProvided && o.CurrentContext != nil && o.CurrentContext.AuthMethod == "aws-iam" && o.CurrentContext.AWSIamArn != "" {
		o.orchestrateAWSIdentity(ctx, restConfig, eksClient)
	}

	// Parse the subject
	subject, err := rbac.ParseSubject(o.As)
	if err != nil {
		return fmt.Errorf("failed to parse subject: %w", err)
	}

	// Pod Identity enrichment: when the resolved subject is a
	// ServiceAccount, surface any IAM role(s) bound to it. Informational —
	// doesn't affect RBAC resolution.
	if eksClient != nil && o.CurrentContext != nil && subject.Kind == "ServiceAccount" && o.CurrentContext.EKSClusterName != "" {
		assocs, err := FindPodIdentityForServiceAccount(ctx, eksClient, o.CurrentContext.EKSClusterName, subject.Namespace, subject.Name)
		if err != nil {
			_, _ = fmt.Fprintf(o.ErrOut, "Warning: failed to list Pod Identity associations for service account: %v\n", err)
		} else {
			o.CurrentContext.PodIdentityForSA = assocs
		}
	}

	// If we extracted groups from the current context (e.g., from client certificate or aws-auth),
	// add them to the subject so they're used in RBAC resolution
	if !o.AsProvided && o.CurrentContext != nil && len(o.CurrentContext.Groups) > 0 {
		subject.Groups = o.CurrentContext.Groups
	}

	rbacClient, err := client.NewK8sRBACClient(restConfig)
	if err != nil {
		return fmt.Errorf("failed to create RBAC client: %w", err)
	}

	resolver := rbac.NewResolver(rbacClient)

	// Handle --show-risky flag
	if o.ShowRisky {
		return o.runRiskyAnalysis(ctx, resolver, subject)
	}

	// Handle --compare-with flag
	if o.CompareWith != "" {
		return o.runCompare(ctx, resolver, subject)
	}

	// Normal permission check
	request := o.ToPermissionRequest()
	result, err := resolver.ResolvePermission(ctx, subject, request)
	if err != nil {
		return fmt.Errorf("failed to resolve permission: %w", err)
	}

	// Print result
	printer, err := output.NewPrinter(o.Output, output.ResolveColor(o.Color, o.Out))
	if err != nil {
		return err
	}

	// Convert context info for output if using current context
	var ctxInfo *output.ContextInfo
	if !o.AsProvided && o.CurrentContext != nil {
		ctxInfo = toOutputContextInfo(o.CurrentContext)
	}

	return printer.Print(o.Out, result, ctxInfo)
}

// toOutputContextInfo translates the cani-internal ContextInfo (which holds
// SDK-typed AccessPolicy/PodIdentity values) into the output package's
// SDK-free representation so pkg/output stays decoupled from the AWS SDK.
func toOutputContextInfo(c *ContextInfo) *output.ContextInfo {
	if c == nil {
		return nil
	}
	out := &output.ContextInfo{
		ContextName:    c.ContextName,
		ClusterName:    c.ClusterName,
		AuthInfo:       c.AuthInfo,
		UserName:       c.UserName,
		Groups:         c.Groups,
		AuthMethod:     c.AuthMethod,
		Namespace:      c.Namespace,
		EKSClusterName: c.EKSClusterName,
	}
	for _, ap := range c.AccessPolicies {
		out.AccessPolicies = append(out.AccessPolicies, output.AccessPolicyInfo{
			PolicyARN:  ap.PolicyARN,
			ScopeType:  ap.ScopeType,
			Namespaces: ap.Namespaces,
		})
	}
	if c.PodIdentityForRole != nil {
		out.PodIdentityForRole = &output.PodIdentityInfo{
			AssociationID:  c.PodIdentityForRole.AssociationID,
			Namespace:      c.PodIdentityForRole.Namespace,
			ServiceAccount: c.PodIdentityForRole.ServiceAccount,
			RoleARN:        c.PodIdentityForRole.RoleARN,
		}
	}
	for _, p := range c.PodIdentityForSA {
		out.PodIdentityForSA = append(out.PodIdentityForSA, output.PodIdentityInfo{
			AssociationID:  p.AssociationID,
			Namespace:      p.Namespace,
			ServiceAccount: p.ServiceAccount,
			RoleARN:        p.RoleARN,
		})
	}
	return out
}

// maybeBuildEKSClient constructs an EKSAPI client when an EKS cluster
// identity is known and EKS lookups aren't disabled. Returns nil (with a
// warning to ErrOut on actual failure) so callers can simply check for
// nil and skip EKS-specific code paths.
func (o *RbacWhyOptions) maybeBuildEKSClient(ctx context.Context) EKSAPI {
	if o.SkipEKS || o.CurrentContext == nil {
		return nil
	}
	if o.CurrentContext.EKSClusterName == "" || o.CurrentContext.EKSRegion == "" {
		return nil
	}
	client, err := eksClientFactory(ctx, o.AWSProfile, o.CurrentContext.EKSRegion)
	if err != nil {
		_, _ = fmt.Fprintf(o.ErrOut, "Warning: failed to build EKS client (%v); skipping Access Entries and Pod Identity lookups\n", err)
		return nil
	}
	return client
}

// orchestrateAWSIdentity resolves the K8s identity for an AWS IAM-authenticated
// caller by walking the priority chain:
//
//  1. EKS Access Entries (modern; via DescribeAccessEntry)
//  2. aws-auth ConfigMap (legacy)
//  3. EKS Pod Identity reverse-lookup (when the IAM principal is a role
//     bound to a ServiceAccount via Pod Identity)
//  4. Raw IAM ARN (fallback — same as today's behavior)
//
// On any per-step error other than "not found", a one-line warning goes to
// ErrOut and resolution falls through to the next step. The function never
// returns an error — failures degrade gracefully, preserving today's
// behavior on non-EKS clusters and clusters without EKS API permissions.
func (o *RbacWhyOptions) orchestrateAWSIdentity(ctx context.Context, restConfig *rest.Config, eksClient EKSAPI) {
	arn := o.CurrentContext.AWSIamArn
	clusterName := o.CurrentContext.EKSClusterName

	// 1. EKS Access Entries
	if eksClient != nil && clusterName != "" {
		ae, err := ResolveAccessEntryIdentity(ctx, eksClient, clusterName, arn)
		if err != nil {
			_, _ = fmt.Fprintf(o.ErrOut, "Warning: failed to query EKS Access Entries: %v\n", err)
		} else if ae.Found {
			o.As = ae.KubernetesUsername
			o.CurrentContext.UserName = ae.KubernetesUsername
			o.CurrentContext.Groups = ae.KubernetesGroups
			o.CurrentContext.AuthMethod = "aws-iam (via Access Entry)"
			o.CurrentContext.AccessEntryFound = true
			o.CurrentContext.AccessPolicies = ae.AccessPolicies
			return
		}
	}

	// 2. aws-auth ConfigMap
	identity, err := ResolveAWSAuthIdentity(ctx, restConfig, arn)
	switch {
	case err == nil && identity.Found:
		o.As = identity.Username
		o.CurrentContext.UserName = identity.Username
		o.CurrentContext.Groups = identity.Groups
		o.CurrentContext.AuthMethod = "aws-iam (via aws-auth)"
		return
	case err == nil && !identity.Found:
		// aws-auth exists but has no entry for this principal; advance
		// to Pod Identity reverse-lookup before giving up.
	case errors.Is(err, ErrAwsAuthNotFound):
		// Modern EKS clusters use Access Entries only and have no
		// aws-auth ConfigMap. This is normal — no warning.
	default:
		_, _ = fmt.Fprintf(o.ErrOut, "Warning: failed to read aws-auth ConfigMap: %v\n", err)
	}

	// 3. Pod Identity reverse-lookup (IAM role → ServiceAccount).
	// Only meaningful when the caller is acting as an IAM role.
	if eksClient != nil && clusterName != "" {
		if matches, perr := FindPodIdentityByRole(ctx, eksClient, clusterName, arn); perr != nil {
			_, _ = fmt.Fprintf(o.ErrOut, "Warning: failed to scan Pod Identity associations: %v\n", perr)
		} else if len(matches) == 1 {
			m := matches[0]
			o.As = "system:serviceaccount:" + m.Namespace + ":" + m.ServiceAccount
			o.CurrentContext.UserName = o.As
			o.CurrentContext.Groups = nil
			o.CurrentContext.AuthMethod = "aws-iam (via Pod Identity)"
			o.CurrentContext.PodIdentityForRole = &m
			return
		} else if len(matches) > 1 {
			_, _ = fmt.Fprintf(o.ErrOut, "Warning: %d Pod Identity associations match this IAM role; ambiguous — falling back to raw IAM ARN\n", len(matches))
		}
	}

	// 4. Raw IAM ARN fallback
	if identity != nil && !identity.Found {
		// aws-auth was readable but had no mapping
		o.As = identity.Username
		o.CurrentContext.UserName = identity.Username
		o.CurrentContext.Groups = identity.Groups
		o.CurrentContext.AuthMethod = "aws-iam (no mapping found)"
		return
	}
	o.As = arn
	o.CurrentContext.UserName = arn
	o.CurrentContext.AuthMethod = "aws-iam (no mapping found)"
}

// runRiskyAnalysis shows risky permissions for a subject
func (o *RbacWhyOptions) runRiskyAnalysis(ctx context.Context, resolver *rbac.Resolver, subject rbac.Subject) error {
	grants, softErrors, err := resolver.ResolveAllPermissions(ctx, subject, o.Namespace, o.AllNamespaces)
	if err != nil {
		return fmt.Errorf("failed to resolve permissions: %w", err)
	}

	// Surface non-fatal errors (e.g. roles we couldn't read) so the user knows
	// the scan may be incomplete rather than trusting a silent "clean" result.
	for _, sErr := range softErrors {
		_, _ = fmt.Fprintf(o.ErrOut, "Warning: %v (risk scan may be incomplete)\n", sErr)
	}

	risks := output.AnalyzeRiskyPermissions(grants)
	output.PrintRiskyPermissions(o.Out, risks, output.ResolveColor(o.Color, o.Out))
	return nil
}

// runWhoCan performs a reverse lookup: which subjects can perform the request.
func (o *RbacWhyOptions) runWhoCan(ctx context.Context, resolver *rbac.Resolver) error {
	result, err := resolver.ResolveSubjectsWithPermission(ctx, o.ToPermissionRequest())
	if err != nil {
		return fmt.Errorf("failed to resolve subjects: %w", err)
	}
	return output.PrintSubjectsWithPermission(o.Out, result, o.Output)
}

// runCompare compares the subject's effective permissions with another subject.
func (o *RbacWhyOptions) runCompare(ctx context.Context, resolver *rbac.Resolver, subject rbac.Subject) error {
	other, err := rbac.ParseSubject(o.CompareWith)
	if err != nil {
		return fmt.Errorf("failed to parse --compare-with subject: %w", err)
	}
	comp, err := resolver.ComparePermissions(ctx, subject, other, o.Namespace, o.AllNamespaces)
	if err != nil {
		return fmt.Errorf("failed to compare permissions: %w", err)
	}
	for _, sErr := range comp.SoftErrors {
		_, _ = fmt.Fprintf(o.ErrOut, "Warning: %v (comparison may be incomplete)\n", sErr)
	}
	return output.PrintComparison(o.Out, comp, o.Output)
}
