package cani

import (
	"fmt"
	"strings"

	"k8s.io/cli-runtime/pkg/genericclioptions"

	"github.com/hardik/kubectl-rbac-why/pkg/rbac"
)

// RbacWhyOptions contains the options for the rbac-why command
type RbacWhyOptions struct {
	// Subject identification (--as flag)
	As string

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
	}

	// Get namespace from ConfigFlags
	if o.ConfigFlags.Namespace != nil && *o.ConfigFlags.Namespace != "" {
		o.Namespace = *o.ConfigFlags.Namespace
	}

	return nil
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
	if o.As == "" {
		return fmt.Errorf("--as is required: specify the subject to check (e.g., --as system:serviceaccount:namespace:name)")
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
