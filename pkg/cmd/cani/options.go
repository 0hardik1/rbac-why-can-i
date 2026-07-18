package cani

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/tools/clientcmd/api"

	"github.com/hardik/kubectl-rbac-why/pkg/rbac"
)

// ContextInfo holds information about the current kubeconfig context
type ContextInfo struct {
	ContextName string
	ClusterName string
	AuthInfo    string   // The kubeconfig authInfo name
	UserName    string   // The actual user identity (e.g., CN from cert)
	Groups      []string // Groups the user belongs to (e.g., O from cert)
	Namespace   string
	AuthMethod  string // e.g., "client-certificate", "token", "exec", etc.
	AWSIamArn   string // For AWS IAM auth: the IAM ARN before aws-auth mapping

	// IdentityResolved is false when UserName is only the kubeconfig authInfo
	// name (token/exec/auth-provider auth), not an actual identity. Run then
	// asks the API server who we are via SelfSubjectReview.
	IdentityResolved bool

	// EKS-specific fields (populated when running against an EKS cluster).
	EKSClusterName     string
	EKSRegion          string
	AccessEntryFound   bool
	AccessPolicies     []AccessPolicyAssociation
	PodIdentityForRole *PodIdentityAssociation  // populated by IAM-role reverse lookup
	PodIdentityForSA   []PodIdentityAssociation // populated by SA enrichment
}

// RbacWhyOptions contains the options for the rbac-why command
type RbacWhyOptions struct {
	// Subject identification (--as flag)
	As string

	// Whether --as was explicitly provided (false means using current context)
	AsProvided bool

	// Groups from --as-group, attached to the subject when --as is provided
	AsGroups []string

	// Current context information (populated when --as is not provided)
	CurrentContext *ContextInfo

	// Permission request
	Verb           string
	Resource       string
	Subresource    string
	APIGroup       string
	ResourceName   string
	NonResourceURL string // set instead of Resource for non-resource URLs (e.g. /healthz)

	// Namespace
	Namespace string

	// Output options
	Output        string // text, json, yaml, dot, mermaid
	Color         string // auto, always, never
	ShowRisky     bool
	WhoCan        bool   // reverse lookup: list subjects that can perform VERB RESOURCE
	AllNamespaces bool   // with --show-risky, scan RoleBindings across all namespaces
	CompareWith   string // compare the subject's effective permissions with another subject

	// AWS options
	AWSProfile  string // AWS profile to use for authentication
	ClusterName string // EKS cluster name override (--cluster-name)
	AWSRegion   string // AWS region override (--region)
	SkipEKS     bool   // skip EKS API lookups (--skip-eks-lookup)

	// Kubernetes config
	ConfigFlags *genericclioptions.ConfigFlags

	// IO streams
	genericclioptions.IOStreams
}

// NewRbacWhyOptions creates default options
func NewRbacWhyOptions(streams genericclioptions.IOStreams) *RbacWhyOptions {
	return &RbacWhyOptions{
		ConfigFlags: genericclioptions.NewConfigFlags(true),
		IOStreams:   streams,
		Output:      "text",
		Color:       "auto",
	}
}

// Complete fills in fields that were not specified
func (o *RbacWhyOptions) Complete(args []string) error {
	// VERB RESOURCE is needed for the normal check and --who-can, but not for
	// whole-subject modes (--show-risky, --compare-with).
	if !o.ShowRisky && o.CompareWith == "" {
		if len(args) < 2 {
			return fmt.Errorf("requires at least 2 arguments: VERB RESOURCE [NAME]")
		}
		if len(args) > 3 {
			return fmt.Errorf("too many arguments: expected VERB RESOURCE [NAME]")
		}

		o.Verb = args[0]
		resourceArg := args[1]

		// Parse resource which may include API group (e.g., "pods.v1" or "deployments.apps")
		if err := o.parseResource(resourceArg); err != nil {
			return err
		}

		if len(args) == 3 {
			if o.NonResourceURL != "" {
				return fmt.Errorf("a resource name cannot be combined with a non-resource URL")
			}
			o.ResourceName = args[2]
		}
	}

	// Get --as value from ConfigFlags
	if o.ConfigFlags.Impersonate != nil && *o.ConfigFlags.Impersonate != "" {
		o.As = *o.ConfigFlags.Impersonate
		o.AsProvided = true
	}

	// Get --as-group values; they participate in group-based binding matches
	if o.ConfigFlags.ImpersonateGroup != nil && len(*o.ConfigFlags.ImpersonateGroup) > 0 {
		o.AsGroups = append([]string(nil), (*o.ConfigFlags.ImpersonateGroup)...)
	}

	// Resolve the effective namespace the way kubectl does: -n flag, then the
	// kubeconfig context's namespace, then "default". Cluster-scoped requests
	// have the namespace cleared later via API discovery.
	if ns, _, err := o.ConfigFlags.ToRawKubeConfigLoader().Namespace(); err == nil && ns != "" {
		o.Namespace = ns
	} else if o.ConfigFlags.Namespace != nil && *o.ConfigFlags.Namespace != "" {
		o.Namespace = *o.ConfigFlags.Namespace
	} else {
		o.Namespace = "default"
	}

	// who-can is a reverse lookup and resolves no subject identity.
	if o.WhoCan {
		return nil
	}

	// If --as is not provided, get subject from current context
	if !o.AsProvided {
		if err := o.completeFromCurrentContext(); err != nil {
			return err
		}
	}

	return nil
}

// completeFromCurrentContext populates options from the current kubeconfig context
func (o *RbacWhyOptions) completeFromCurrentContext() error {
	rawConfig, err := o.ConfigFlags.ToRawKubeConfigLoader().RawConfig()
	if err != nil {
		return fmt.Errorf("failed to load kubeconfig: %w", err)
	}

	currentContextName := rawConfig.CurrentContext
	if currentContextName == "" {
		return fmt.Errorf("no current context set in kubeconfig; use --as to specify a subject")
	}

	currentContext, exists := rawConfig.Contexts[currentContextName]
	if !exists {
		return fmt.Errorf("current context %q not found in kubeconfig", currentContextName)
	}

	// Get the authInfo name from the context
	authInfoName := currentContext.AuthInfo
	if authInfoName == "" {
		return fmt.Errorf("no user specified in current context %q; use --as to specify a subject", currentContextName)
	}

	// Get the authInfo details
	authInfo, exists := rawConfig.AuthInfos[authInfoName]
	if !exists {
		return fmt.Errorf("auth info %q not found in kubeconfig", authInfoName)
	}

	// Try to determine the actual user identity
	userName, groups, authMethod, resolved := extractUserIdentity(authInfo, authInfoName, o.AWSProfile)

	// Store context info for display
	o.CurrentContext = &ContextInfo{
		ContextName:      currentContextName,
		ClusterName:      currentContext.Cluster,
		AuthInfo:         authInfoName,
		UserName:         userName,
		Groups:           groups,
		Namespace:        currentContext.Namespace,
		AuthMethod:       authMethod,
		IdentityResolved: resolved,
	}

	// For AWS IAM auth, store the IAM ARN for later aws-auth lookup
	if authMethod == "aws-iam" {
		o.CurrentContext.AWSIamArn = userName
	}

	// Derive EKS cluster identity from kubeconfig (used by Access Entries
	// and Pod Identity lookups). User-supplied --cluster-name / --region
	// flags take precedence and are applied here.
	if id, ok := DeriveClusterIdentity(rawConfig, currentContextName); ok {
		o.CurrentContext.EKSClusterName = id.ClusterName
		o.CurrentContext.EKSRegion = id.Region
	}
	if o.ClusterName != "" {
		o.CurrentContext.EKSClusterName = o.ClusterName
	}
	if o.AWSRegion != "" {
		o.CurrentContext.EKSRegion = o.AWSRegion
	}

	// Use the extracted user name as the subject
	o.As = userName

	return nil
}

// extractUserIdentity tries to determine the actual user identity from authInfo.
// Returns: userName, groups, authMethod, resolved. When resolved is false the
// userName is only the kubeconfig authInfo entry name, which has no required
// relationship to the authenticated identity; callers should confirm the real
// identity with the API server (SelfSubjectReview).
func extractUserIdentity(authInfo *api.AuthInfo, fallbackName string, awsProfile string) (string, []string, string, bool) {
	// Try client certificate first (most common for local clusters like Docker Desktop, kind, minikube)
	if len(authInfo.ClientCertificateData) > 0 {
		if userName, groups, err := parseClientCertificate(authInfo.ClientCertificateData); err == nil {
			return userName, groups, "client-certificate", true
		}
	}

	// Try certificate file
	if authInfo.ClientCertificate != "" {
		certData, err := os.ReadFile(authInfo.ClientCertificate)
		if err == nil {
			if userName, groups, err := parseClientCertificate(certData); err == nil {
				return userName, groups, "client-certificate", true
			}
		}
	}

	// Token-based auth - we can't determine the user without calling the API
	if authInfo.Token != "" || authInfo.TokenFile != "" {
		return fallbackName, nil, "token", false
	}

	// Exec-based auth (e.g., aws-iam-authenticator, gcloud)
	if authInfo.Exec != nil {
		// Try to extract identity for AWS IAM authenticator
		if isAWSAuth(authInfo.Exec) {
			if userName, groups, err := extractAWSIdentity(authInfo.Exec, awsProfile); err == nil {
				return userName, groups, "aws-iam", true
			}
			// Fall through to fallback if AWS identity extraction fails
		}
		return fallbackName, nil, "exec (" + authInfo.Exec.Command + ")", false
	}

	// Auth provider (e.g., oidc, gcp)
	if authInfo.AuthProvider != nil {
		return fallbackName, nil, "auth-provider (" + authInfo.AuthProvider.Name + ")", false
	}

	// Fallback to the authInfo name
	return fallbackName, nil, "unknown", false
}

// parseClientCertificate extracts the CN (user) and O (groups) from a client certificate
func parseClientCertificate(certData []byte) (string, []string, error) {
	block, _ := pem.Decode(certData)
	if block == nil {
		return "", nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	userName := cert.Subject.CommonName
	if userName == "" {
		return "", nil, fmt.Errorf("certificate has no CommonName")
	}

	// Organizations become groups in Kubernetes RBAC
	groups := cert.Subject.Organization

	return userName, groups, nil
}

// isAWSAuth checks if the exec config is for AWS IAM authentication
func isAWSAuth(execConfig *api.ExecConfig) bool {
	cmd := execConfig.Command
	// Check for aws-iam-authenticator
	if cmd == "aws-iam-authenticator" || strings.HasSuffix(cmd, "/aws-iam-authenticator") {
		return true
	}
	return isEKSGetToken(execConfig)
}

// isEKSGetToken checks if the exec config runs `aws eks get-token`
func isEKSGetToken(execConfig *api.ExecConfig) bool {
	cmd := execConfig.Command
	if cmd == "aws" || strings.HasSuffix(cmd, "/aws") {
		for i, arg := range execConfig.Args {
			if arg == "eks" && i+1 < len(execConfig.Args) && execConfig.Args[i+1] == "get-token" {
				return true
			}
		}
	}
	return false
}

// stsGetCallerIdentityResponse represents the response from aws sts get-caller-identity
type stsGetCallerIdentityResponse struct {
	Account string `json:"Account"`
	Arn     string `json:"Arn"`
	UserId  string `json:"UserId"`
}

// extractAWSIdentity extracts the AWS IAM identity using aws sts get-caller-identity
// It also checks if a role is being assumed via the exec config
// awsProfile is the profile from --profile flag, if empty will try to extract from exec args
func extractAWSIdentity(execConfig *api.ExecConfig, awsProfile string) (string, []string, error) {
	// Check if a role is specified in the exec arguments
	roleArn := extractRoleFromArgs(execConfig.Args)

	// Get profile: prefer flag, then exec args
	profile := awsProfile
	if profile == "" {
		profile = extractProfileFromArgs(execConfig.Args)
	}

	// Also check environment variables in exec config
	var envVars []string
	for _, env := range execConfig.Env {
		envVars = append(envVars, env.Name+"="+env.Value)
	}

	// Build aws sts get-caller-identity command
	cmdArgs := []string{"sts", "get-caller-identity", "--output", "json"}
	if profile != "" {
		cmdArgs = append(cmdArgs, "--profile", profile)
	}

	cmd := exec.Command("aws", cmdArgs...)
	cmd.Env = append(os.Environ(), envVars...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", nil, fmt.Errorf("failed to get AWS caller identity: %w (stderr: %s)", err, stderr.String())
	}

	var response stsGetCallerIdentityResponse
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		return "", nil, fmt.Errorf("failed to parse AWS caller identity: %w", err)
	}

	// If a role is specified in the exec config, use that role ARN
	// The actual username in K8s will be the assumed-role ARN
	if roleArn != "" {
		// For assumed roles, the Kubernetes-visible caller ARN is
		// arn:PARTITION:sts::ACCOUNT:assumed-role/ROLE-NAME/SESSION-NAME.
		// Partition and account come from the role ARN itself (the role may
		// live in another account or partition than the base caller).
		// `aws eks get-token` always uses the session name EKSGetTokenAuth;
		// for other tools the session is unknowable and omitted.
		sessionName := ""
		if isEKSGetToken(execConfig) {
			sessionName = "EKSGetTokenAuth"
		}
		userName := convertRoleToAssumedRoleArn(roleArn, response.Account, sessionName)
		return userName, nil, nil
	}

	// For IAM users or roles (when not assuming a different role),
	// the Arn from get-caller-identity is the username
	return response.Arn, nil, nil
}

// extractRoleFromArgs looks for role ARN in exec arguments
// Supports: -r ARN, --role ARN, --role-arn ARN, -r=ARN, --role=ARN, --role-arn=ARN
func extractRoleFromArgs(args []string) string {
	for i, arg := range args {
		// Handle -r ARN or --role ARN or --role-arn ARN
		if (arg == "-r" || arg == "--role" || arg == "--role-arn") && i+1 < len(args) {
			return args[i+1]
		}
		// Handle -r=ARN or --role=ARN or --role-arn=ARN
		for _, prefix := range []string{"-r=", "--role=", "--role-arn="} {
			if strings.HasPrefix(arg, prefix) {
				return strings.TrimPrefix(arg, prefix)
			}
		}
	}
	return ""
}

// extractProfileFromArgs looks for AWS profile in exec arguments
// Supports: --profile NAME, --profile=NAME (used by both aws cli and aws-iam-authenticator)
func extractProfileFromArgs(args []string) string {
	for i, arg := range args {
		// Handle --profile NAME
		if arg == "--profile" && i+1 < len(args) {
			return args[i+1]
		}
		// Handle --profile=NAME
		if strings.HasPrefix(arg, "--profile=") {
			return strings.TrimPrefix(arg, "--profile=")
		}
	}
	return ""
}

// parseResource parses a resource string like "pods", "pods/log", "deployments.apps".
// A leading "/" marks a non-resource URL (e.g. "/healthz", "/metrics", "/api/*"),
// which has no API group or subresource.
func (o *RbacWhyOptions) parseResource(resource string) error {
	// Non-resource URL (e.g. "/healthz")
	if strings.HasPrefix(resource, "/") {
		if o.Subresource != "" {
			return fmt.Errorf("--subresource cannot be combined with a non-resource URL")
		}
		o.NonResourceURL = resource
		return nil
	}

	// Handle subresource (e.g., "pods/exec"). Note this differs from
	// `kubectl auth can-i`, where TYPE/NAME denotes a resource name; here the
	// resource name is the optional third argument and --subresource is also
	// accepted for kubectl parity.
	if idx := strings.Index(resource, "/"); idx != -1 {
		if o.Subresource != "" {
			return fmt.Errorf("cannot combine RESOURCE/SUBRESOURCE syntax with --subresource")
		}
		o.Resource = resource[:idx]
		o.Subresource = resource[idx+1:]
		resource = o.Resource
	} else {
		o.Resource = resource
	}

	// Handle API group (e.g., "deployments.apps" or "deployments.apps/v1")
	if res, group, ok := strings.Cut(resource, "."); ok {
		o.Resource = res
		o.APIGroup = group
		// Remove version if present (e.g., "apps/v1" -> "apps")
		if g, _, ok := strings.Cut(o.APIGroup, "/"); ok {
			o.APIGroup = g
		}
	}

	return nil
}

// Validate checks that the options are valid
func (o *RbacWhyOptions) Validate() error {
	// At most one special mode at a time.
	modes := 0
	if o.ShowRisky {
		modes++
	}
	if o.WhoCan {
		modes++
	}
	if o.CompareWith != "" {
		modes++
	}
	if modes > 1 {
		return fmt.Errorf("--show-risky, --who-can, and --compare-with are mutually exclusive")
	}

	switch o.Color {
	case "", "auto", "always", "never":
	default:
		return fmt.Errorf("invalid --color value %q (valid: auto, always, never)", o.Color)
	}

	// Every mode except who-can resolves and needs a subject.
	if !o.WhoCan && o.As == "" {
		return fmt.Errorf("could not determine subject: either use --as flag or ensure kubeconfig has a valid current context")
	}

	// VERB RESOURCE is required for the normal check and for --who-can, but not
	// for whole-subject modes (--show-risky, --compare-with).
	if !o.ShowRisky && o.CompareWith == "" {
		if o.Verb == "" {
			return fmt.Errorf("verb is required")
		}
		if o.Resource == "" && o.NonResourceURL == "" {
			return fmt.Errorf("resource is required (a resource like \"pods\" or a non-resource URL like \"/healthz\")")
		}
	}

	// who-can and compare-with render their own output, supporting a subset of formats.
	if o.WhoCan || o.CompareWith != "" {
		switch o.Output {
		case "text", "json", "yaml":
			return nil
		default:
			return fmt.Errorf("this mode supports output formats text, json, yaml (got %q)", o.Output)
		}
	}

	validOutputs := map[string]bool{
		"text": true, "json": true, "yaml": true, "dot": true, "mermaid": true,
	}
	if !validOutputs[o.Output] {
		return fmt.Errorf("invalid output format: %s (valid: text, json, yaml, dot, mermaid)", o.Output)
	}

	return nil
}

// ToPermissionRequest converts options to a PermissionRequest
func (o *RbacWhyOptions) ToPermissionRequest() rbac.PermissionRequest {
	return rbac.PermissionRequest{
		Verb:           o.Verb,
		APIGroup:       o.APIGroup,
		Resource:       o.Resource,
		Subresource:    o.Subresource,
		ResourceName:   o.ResourceName,
		Namespace:      o.Namespace,
		NonResourceURL: o.NonResourceURL,
	}
}
