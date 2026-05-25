package cani

import (
	"testing"

	"k8s.io/client-go/tools/clientcmd/api"
)

func TestParseResource(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		resource    string
		subresource string
		apiGroup    string
		nonResource string
	}{
		{name: "plain resource", input: "pods", resource: "pods"},
		{name: "subresource", input: "pods/exec", resource: "pods", subresource: "exec"},
		{name: "dotted api group", input: "deployments.apps", resource: "deployments", apiGroup: "apps"},
		{name: "non-resource url", input: "/healthz", nonResource: "/healthz"},
		{name: "non-resource url wildcard", input: "/api/*", nonResource: "/api/*"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &RbacWhyOptions{}
			if err := o.parseResource(tt.input); err != nil {
				t.Fatalf("parseResource(%q) error: %v", tt.input, err)
			}
			if o.Resource != tt.resource {
				t.Errorf("Resource = %q, want %q", o.Resource, tt.resource)
			}
			if o.Subresource != tt.subresource {
				t.Errorf("Subresource = %q, want %q", o.Subresource, tt.subresource)
			}
			if o.APIGroup != tt.apiGroup {
				t.Errorf("APIGroup = %q, want %q", o.APIGroup, tt.apiGroup)
			}
			if o.NonResourceURL != tt.nonResource {
				t.Errorf("NonResourceURL = %q, want %q", o.NonResourceURL, tt.nonResource)
			}
		})
	}
}

func TestExtractRoleFromArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "space form --role", args: []string{"--role", "arn:aws:iam::1:role/x"}, want: "arn:aws:iam::1:role/x"},
		{name: "equals form --role-arn", args: []string{"--role-arn=arn:y"}, want: "arn:y"},
		{name: "short -r", args: []string{"-r", "arn:z"}, want: "arn:z"},
		{name: "none", args: []string{"eks", "get-token"}, want: ""},
		{name: "empty", args: nil, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractRoleFromArgs(tt.args); got != tt.want {
				t.Errorf("extractRoleFromArgs(%v) = %q, want %q", tt.args, got, tt.want)
			}
		})
	}
}

func TestExtractProfileFromArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "space form", args: []string{"--profile", "dev"}, want: "dev"},
		{name: "equals form", args: []string{"--profile=prod"}, want: "prod"},
		{name: "none", args: []string{"eks", "get-token"}, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractProfileFromArgs(tt.args); got != tt.want {
				t.Errorf("extractProfileFromArgs(%v) = %q, want %q", tt.args, got, tt.want)
			}
		})
	}
}

func TestIsAWSAuth(t *testing.T) {
	tests := []struct {
		name string
		exec *api.ExecConfig
		want bool
	}{
		{
			name: "aws eks get-token",
			exec: &api.ExecConfig{Command: "aws", Args: []string{"eks", "get-token", "--cluster-name", "c"}},
			want: true,
		},
		{
			name: "aws-iam-authenticator",
			exec: &api.ExecConfig{Command: "aws-iam-authenticator", Args: []string{"token", "-i", "c"}},
			want: true,
		},
		{
			name: "absolute path to aws",
			exec: &api.ExecConfig{Command: "/usr/local/bin/aws", Args: []string{"eks", "get-token"}},
			want: true,
		},
		{
			name: "aws sts (not eks get-token)",
			exec: &api.ExecConfig{Command: "aws", Args: []string{"sts", "get-caller-identity"}},
			want: false,
		},
		{
			name: "gcloud auth plugin",
			exec: &api.ExecConfig{Command: "gke-gcloud-auth-plugin"},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isAWSAuth(tt.exec); got != tt.want {
				t.Errorf("isAWSAuth(%s) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
