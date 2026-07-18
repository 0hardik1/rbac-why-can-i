package cani

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/rest"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

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

  # Check access to one specific secret (matches RBAC resourceNames rules)
  kubectl rbac-why can-i get secrets db-password -n default

  # Output as JSON for programmatic use
  kubectl rbac-why can-i get pods -o json

  # Generate a DOT graph
  kubectl rbac-why can-i get pods -o dot | dot -Tpng > rbac.png

  # Generate a Mermaid diagram
  kubectl rbac-why can-i get pods -o mermaid

  # Show risky permissions for a subject
  kubectl rbac-why can-i --as system:serviceaccount:default:my-sa --show-risky -n default

  # Show risky permissions for current user
  kubectl rbac-why can-i --show-risky -n default`
)

// NewCmdRbacWhy creates the rbac-why root command
func NewCmdRbacWhy(streams genericclioptions.IOStreams) *cobra.Command {
	o := NewRbacWhyOptions(streams)

	cmd := &cobra.Command{
		Use:     "rbac-why can-i [--as SUBJECT] VERB RESOURCE [NAME] [flags]",
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
	cmd.Flags().StringVar(&o.Subresource, "subresource", "", "Subresource to check (e.g. status, log, exec); alternative to RESOURCE/SUBRESOURCE syntax")
	cmd.Flags().BoolVar(&o.ShowRisky, "show-risky", false, "Analyze and show risky permissions for the subject")
	cmd.Flags().StringVarP(&o.AWSProfile, "profile", "p", "", "AWS profile to use for authentication (for EKS clusters)")
	cmd.Flags().StringVar(&o.ClusterName, "cluster-name", "", "EKS cluster name (overrides auto-detection from kubeconfig)")
	cmd.Flags().StringVar(&o.AWSRegion, "region", "", "AWS region for EKS API calls (overrides auto-detection)")
	cmd.Flags().BoolVar(&o.SkipEKS, "skip-eks-lookup", false, "Skip EKS Access Entries and Pod Identity lookups")

	return cmd
}

// Run executes the rbac-why command
func (o *RbacWhyOptions) Run(ctx context.Context) error {
	restConfig, err := o.ConfigFlags.ToRESTConfig()
	if err != nil {
		return fmt.Errorf("failed to create REST config: %w", err)
	}

	// Create the Kubernetes client WITHOUT impersonation: RBAC objects must
	// be read with the caller's real permissions, never as the subject being
	// investigated (which would limit the walk to whatever the subject can
	// see). Clearing the built config is the reliable way to do this;
	// ConfigFlags caches its kubeconfig loader, so clearing the flag values
	// before ToRESTConfig does not work once the loader has been built.
	restConfig.Impersonate = rest.ImpersonationConfig{}

	// Make the kubeconfig's AWS exec credential plugin honor --profile, so
	// the Kubernetes client authenticates as the same AWS principal that the
	// local STS/EKS identity lookups use.
	if o.AWSProfile != "" {
		injectAWSProfile(restConfig, o.AWSProfile)
	}

	// Build an EKS client once and reuse it for both identity resolution
	// and ServiceAccount enrichment. nil if EKS isn't applicable (no
	// cluster name, --skip-eks-lookup, or AWS config error).
	eksClient := o.maybeBuildEKSClient(ctx)

	// For AWS IAM auth, resolve the K8s identity by walking the priority
	// chain: Access Entry -> aws-auth -> raw IAM ARN.
	if !o.AsProvided && o.CurrentContext != nil && o.CurrentContext.AuthMethod == "aws-iam" && o.CurrentContext.AWSIamArn != "" {
		o.orchestrateAWSIdentity(ctx, restConfig, eksClient)
	}

	// When the kubeconfig couldn't yield a real identity (token, generic
	// exec, OIDC/auth-provider), the fallback is just the authInfo entry
	// name, which has no required relationship to the authenticated user.
	// Ask the API server who we are instead.
	if !o.AsProvided && o.CurrentContext != nil && !o.CurrentContext.IdentityResolved {
		if userName, groups, ssrErr := resolveSelfSubject(ctx, restConfig); ssrErr != nil {
			_, _ = fmt.Fprintf(o.ErrOut, "Warning: SelfSubjectReview failed (%v); falling back to kubeconfig authInfo name %q which may not match the authenticated identity\n", ssrErr, o.As)
		} else {
			o.As = userName
			o.CurrentContext.UserName = userName
			o.CurrentContext.Groups = groups
			o.CurrentContext.AuthMethod += " (identity via SelfSubjectReview)"
			o.CurrentContext.IdentityResolved = true
		}
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

	// --as-group values accompany an explicit --as subject
	if o.AsProvided && len(o.AsGroups) > 0 {
		subject.Groups = o.AsGroups
	}

	rbacClient, err := client.NewK8sRBACClient(restConfig)
	if err != nil {
		return fmt.Errorf("failed to create RBAC client: %w", err)
	}

	resolver := rbac.NewResolver(rbacClient)

	// Handle --show-risky flag
	if o.ShowRisky {
		return o.runRiskyAnalysis(ctx, rbacClient, resolver, subject)
	}

	// Normal permission check. Align the request with the cluster's API
	// surface first (resolve the API group, drop the namespace for
	// cluster-scoped resources).
	request := o.ToPermissionRequest()
	o.applyDiscovery(restConfig, &request)

	result, err := resolver.ResolvePermission(ctx, subject, request)
	if err != nil {
		return fmt.Errorf("failed to resolve permission: %w", err)
	}

	// EKS access policies grant permissions additively with RBAC; fold any
	// matching policy grants into the result so an access-policy-only admin
	// isn't reported as denied.
	if o.CurrentContext != nil && len(o.CurrentContext.AccessPolicies) > 0 {
		policyGrants, policyErrs := accessPolicyGrants(ctx, rbacClient, o.CurrentContext.AccessPolicies, o.CurrentContext.AWSIamArn, request.Namespace, &request)
		result.Grants = append(result.Grants, policyGrants...)
		result.Errors = append(result.Errors, policyErrs...)
		result.Allowed = len(result.Grants) > 0
	}

	// Print result
	printer, err := output.NewPrinter(o.Output)
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
//  3. Raw IAM ARN (fallback, same as today's behavior)
//
// Pod Identity associations are surfaced informationally only: Pod Identity
// supplies AWS credentials to pods and does not authenticate an IAM caller as
// the associated ServiceAccount (the same role can also back several SAs).
//
// On any per-step error other than "not found", a one-line warning goes to
// ErrOut and resolution falls through to the next step. The function never
// returns an error, failures degrade gracefully, preserving today's
// behavior on non-EKS clusters and clusters without EKS API permissions.
func (o *RbacWhyOptions) orchestrateAWSIdentity(ctx context.Context, restConfig *rest.Config, eksClient EKSAPI) {
	arn := o.CurrentContext.AWSIamArn
	clusterName := o.CurrentContext.EKSClusterName

	// 1. EKS Access Entries
	if eksClient != nil && clusterName != "" {
		ae, err := ResolveAccessEntryIdentity(ctx, eksClient, clusterName, arn)
		if ae != nil && ae.Found {
			// The username/groups are authoritative even if listing the
			// associated policies failed; don't discard the identity.
			if err != nil {
				_, _ = fmt.Fprintf(o.ErrOut, "Warning: %v\n", err)
			}
			o.As = ae.KubernetesUsername
			o.CurrentContext.UserName = ae.KubernetesUsername
			o.CurrentContext.Groups = ae.KubernetesGroups
			o.CurrentContext.AuthMethod = "aws-iam (via Access Entry)"
			o.CurrentContext.AccessEntryFound = true
			o.CurrentContext.AccessPolicies = ae.AccessPolicies
			return
		}
		if err != nil {
			_, _ = fmt.Fprintf(o.ErrOut, "Warning: failed to query EKS Access Entries: %v\n", err)
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
		// aws-auth exists but has no entry for this principal.
	case errors.Is(err, ErrAwsAuthNotFound):
		// Modern EKS clusters use Access Entries only and have no
		// aws-auth ConfigMap. This is normal, no warning.
	default:
		_, _ = fmt.Fprintf(o.ErrOut, "Warning: failed to read aws-auth ConfigMap: %v\n", err)
	}

	// Informational: note Pod Identity associations for this IAM role so the
	// output can hint at where the role is used. This never rewrites the
	// caller's identity.
	if eksClient != nil && clusterName != "" {
		if matches, perr := FindPodIdentityByRole(ctx, eksClient, clusterName, arn); perr != nil {
			_, _ = fmt.Fprintf(o.ErrOut, "Warning: failed to scan Pod Identity associations: %v\n", perr)
		} else if len(matches) > 0 {
			o.CurrentContext.PodIdentityForRole = &matches[0]
			_, _ = fmt.Fprintf(o.ErrOut, "Note: this IAM role backs %d Pod Identity association(s) (e.g. %s/%s); that does not authenticate this caller as that ServiceAccount\n",
				len(matches), matches[0].Namespace, matches[0].ServiceAccount)
		}
	}

	// 3. Raw IAM ARN fallback
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
func (o *RbacWhyOptions) runRiskyAnalysis(ctx context.Context, rbacClient client.RBACClient, resolver *rbac.Resolver, subject rbac.Subject) error {
	grants, resolveErrs, err := resolver.ResolveAllPermissions(ctx, subject, o.Namespace)
	if err != nil {
		return fmt.Errorf("failed to resolve permissions: %w", err)
	}

	// EKS access policies grant permissions outside the RBAC object chain;
	// include their effective rules so the risk report covers them.
	if o.CurrentContext != nil && len(o.CurrentContext.AccessPolicies) > 0 {
		policyGrants, policyErrs := accessPolicyGrants(ctx, rbacClient, o.CurrentContext.AccessPolicies, o.CurrentContext.AWSIamArn, o.Namespace, nil)
		grants = append(grants, policyGrants...)
		resolveErrs = append(resolveErrs, policyErrs...)
	}

	risks := output.AnalyzeRiskyPermissions(grants)
	output.PrintRiskyPermissions(o.Out, risks, resolveErrs)
	return nil
}

// injectAWSProfile rewrites the REST config's AWS exec credential plugin so
// it uses the given profile: an existing --profile argument is replaced,
// otherwise AWS_PROFILE is set in the plugin's environment. No-op for
// non-AWS exec plugins.
func injectAWSProfile(restConfig *rest.Config, profile string) {
	execProvider := restConfig.ExecProvider
	if execProvider == nil || !isAWSAuth(execProvider) {
		return
	}

	for i, arg := range execProvider.Args {
		if arg == "--profile" && i+1 < len(execProvider.Args) {
			execProvider.Args[i+1] = profile
			return
		}
		if strings.HasPrefix(arg, "--profile=") {
			execProvider.Args[i] = "--profile=" + profile
			return
		}
	}

	for i, env := range execProvider.Env {
		if env.Name == "AWS_PROFILE" {
			execProvider.Env[i].Value = profile
			return
		}
	}
	execProvider.Env = append(execProvider.Env, clientcmdapi.ExecEnvVar{Name: "AWS_PROFILE", Value: profile})
}
