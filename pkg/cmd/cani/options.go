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
}

// RbacWhyOptions contains the options for the rbac-why command
type RbacWhyOptions struct {
	// Subject identification (--as flag)
	As string

	// Whether --as was explicitly provided (false means using current context)
	AsProvided bool

	// Current context information (populated when --as is not provided)
	CurrentContext *ContextInfo

	// Permission request
	Verb        string
	Resource    string
	Subresource string
	APIGroup    string

	// Namespace
	Namespace string

	// Output options
	Output    string // text, json, yaml, dot, mermaid
	ShowRisky bool

	// AWS options
	AWSProfile string // AWS profile to use for authentication

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
	}
}

// Complete fills in fields that were not specified
func (o *RbacWhyOptions) Complete(args []string) error {
	// For --show-risky, we don't need VERB RESOURCE
	if !o.ShowRisky {
		if len(args) < 2 {
			return fmt.Errorf("requires at least 2 arguments: VERB RESOURCE")
		}

		o.Verb = args[0]
		resourceArg := args[1]

		// Parse resource which may include API group (e.g., "pods.v1" or "deployments.apps")
		if err := o.parseResource(resourceArg); err != nil {
			return err
		}
	}

	// Get --as value from ConfigFlags
	if o.ConfigFlags.Impersonate != nil && *o.ConfigFlags.Impersonate != "" {
		o.As = *o.ConfigFlags.Impersonate
		o.AsProvided = true
	}

	// Get namespace from ConfigFlags
	if o.ConfigFlags.Namespace != nil && *o.ConfigFlags.Namespace != "" {
		o.Namespace = *o.ConfigFlags.Namespace
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
	userName, groups, authMethod := extractUserIdentity(authInfo, authInfoName, o.AWSProfile)

	// Store context info for display
	o.CurrentContext = &ContextInfo{
		ContextName: currentContextName,
		ClusterName: currentContext.Cluster,
		AuthInfo:    authInfoName,
		UserName:    userName,
		Groups:      groups,
		Namespace:   currentContext.Namespace,
		AuthMethod:  authMethod,
	}

	// For AWS IAM auth, store the IAM ARN for later aws-auth lookup
	if authMethod == "aws-iam" {
		o.CurrentContext.AWSIamArn = userName
	}

	// Use the extracted user name as the subject
	o.As = userName

	// If namespace not specified via flag, use context's default namespace
	if o.Namespace == "" && currentContext.Namespace != "" {
		o.Namespace = currentContext.Namespace
	}

	return nil
}

// extractUserIdentity tries to determine the actual user identity from authInfo
// Returns: userName, groups, authMethod
func extractUserIdentity(authInfo *api.AuthInfo, fallbackName string, awsProfile string) (string, []string, string) {
	// Try client certificate first (most common for local clusters like Docker Desktop, kind, minikube)
	if len(authInfo.ClientCertificateData) > 0 {
		if userName, groups, err := parseClientCertificate(authInfo.ClientCertificateData); err == nil {
			return userName, groups, "client-certificate"
		}
	}

	// Try certificate file
	if authInfo.ClientCertificate != "" {
		certData, err := os.ReadFile(authInfo.ClientCertificate)
		if err == nil {
			if userName, groups, err := parseClientCertificate(certData); err == nil {
				return userName, groups, "client-certificate"
			}
		}
	}

	// Token-based auth - we can't determine the user without calling the API
	if authInfo.Token != "" || authInfo.TokenFile != "" {
		return fallbackName, nil, "token"
	}

	// Exec-based auth (e.g., aws-iam-authenticator, gcloud)
	if authInfo.Exec != nil {
		// Try to extract identity for AWS IAM authenticator
		if isAWSAuth(authInfo.Exec) {
			if userName, groups, err := extractAWSIdentity(authInfo.Exec, awsProfile); err == nil {
				return userName, groups, "aws-iam"
			}
			// Fall through to fallback if AWS identity extraction fails
		}
		return fallbackName, nil, "exec (" + authInfo.Exec.Command + ")"
	}

	// Auth provider (e.g., oidc, gcp)
	if authInfo.AuthProvider != nil {
		return fallbackName, nil, "auth-provider (" + authInfo.AuthProvider.Name + ")"
	}

	// Fallback to the authInfo name
	return fallbackName, nil, "unknown"
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
	// Check for aws eks get-token
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
		// For assumed roles, Kubernetes username format is:
		// arn:aws:sts::ACCOUNT:assumed-role/ROLE-NAME/SESSION-NAME
		// The session name varies, but we can construct a pattern
		userName := convertRoleToAssumedRoleArn(roleArn, response.Account)
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

// convertRoleToAssumedRoleArn converts a role ARN to the assumed-role ARN format
// that Kubernetes uses as the username
// Input:  arn:aws:iam::123456789012:role/my-role
// Output: arn:aws:sts::123456789012:assumed-role/my-role/*
// Note: We use * as session name placeholder since we can't know the exact session
func convertRoleToAssumedRoleArn(roleArn, accountId string) string {
	// Extract role name from role ARN
	// Format: arn:aws:iam::ACCOUNT:role/ROLE-NAME
	parts := strings.Split(roleArn, "/")
	if len(parts) < 2 {
		return roleArn // Return as-is if we can't parse
	}
	roleName := parts[len(parts)-1]

	// Construct assumed-role ARN
	// When checking RBAC, aws-auth configmap typically maps to:
	// arn:aws:sts::ACCOUNT:assumed-role/ROLE-NAME/SESSION
	// For RBAC lookup, we need to check as the user would appear
	return fmt.Sprintf("arn:aws:sts::%s:assumed-role/%s", accountId, roleName)
}

// parseResource parses a resource string like "pods", "pods/log", "deployments.apps"
func (o *RbacWhyOptions) parseResource(resource string) error {
	// Handle subresource (e.g., "pods/exec")
	if idx := strings.Index(resource, "/"); idx != -1 {
		o.Resource = resource[:idx]
		o.Subresource = resource[idx+1:]
		resource = o.Resource
	} else {
		o.Resource = resource
	}

	// Handle API group (e.g., "deployments.apps" or "deployments.apps/v1")
	if idx := strings.Index(resource, "."); idx != -1 {
		o.Resource = resource[:idx]
		o.APIGroup = resource[idx+1:]
		// Remove version if present (e.g., "apps/v1" -> "apps")
		if vIdx := strings.Index(o.APIGroup, "/"); vIdx != -1 {
			o.APIGroup = o.APIGroup[:vIdx]
		}
	}

	return nil
}

// Validate checks that the options are valid
func (o *RbacWhyOptions) Validate() error {
	// At this point, o.As should be set either from --as flag or from current context
	if o.As == "" {
		return fmt.Errorf("could not determine subject: either use --as flag or ensure kubeconfig has a valid current context")
	}

	// For --show-risky, we don't need verb/resource
	if !o.ShowRisky {
		if o.Verb == "" {
			return fmt.Errorf("verb is required")
		}

		if o.Resource == "" {
			return fmt.Errorf("resource is required")
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
		Verb:        o.Verb,
		APIGroup:    o.APIGroup,
		Resource:    o.Resource,
		Subresource: o.Subresource,
		Namespace:   o.Namespace,
	}
}
