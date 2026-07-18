package cani

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/rest"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// writeTestKubeconfig writes a minimal kubeconfig and returns its path.
func writeTestKubeconfig(t *testing.T, contextNamespace string) string {
	t.Helper()
	ns := ""
	if contextNamespace != "" {
		ns = "\n    namespace: " + contextNamespace
	}
	content := `apiVersion: v1
kind: Config
current-context: test
contexts:
- name: test
  context:
    cluster: test
    user: test` + ns + `
clusters:
- name: test
  cluster:
    server: https://127.0.0.1:6443
users:
- name: test
  user:
    token: abc
`
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func newTestOptions(t *testing.T, kubeconfig string) *RbacWhyOptions {
	t.Helper()
	o := NewRbacWhyOptions(genericclioptions.IOStreams{
		In:     bytes.NewBuffer(nil),
		Out:    bytes.NewBuffer(nil),
		ErrOut: bytes.NewBuffer(nil),
	})
	o.ConfigFlags.KubeConfig = &kubeconfig
	return o
}

func TestComplete_NamespaceDefaultsToDefault(t *testing.T) {
	o := newTestOptions(t, writeTestKubeconfig(t, ""))
	as := "jane"
	o.ConfigFlags.Impersonate = &as
	if err := o.Complete([]string{"get", "pods"}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if o.Namespace != "default" {
		t.Errorf("Namespace = %q, want \"default\"", o.Namespace)
	}
}

func TestComplete_NamespaceFromContextEvenWithAs(t *testing.T) {
	o := newTestOptions(t, writeTestKubeconfig(t, "team-a"))
	as := "jane"
	o.ConfigFlags.Impersonate = &as
	if err := o.Complete([]string{"get", "pods"}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if o.Namespace != "team-a" {
		t.Errorf("Namespace = %q, want \"team-a\" (context namespace must apply with --as)", o.Namespace)
	}
}

func TestComplete_NamespaceFlagWins(t *testing.T) {
	o := newTestOptions(t, writeTestKubeconfig(t, "team-a"))
	as := "jane"
	nsFlag := "team-b"
	o.ConfigFlags.Impersonate = &as
	o.ConfigFlags.Namespace = &nsFlag
	if err := o.Complete([]string{"get", "pods"}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if o.Namespace != "team-b" {
		t.Errorf("Namespace = %q, want \"team-b\"", o.Namespace)
	}
}

func TestComplete_ResourceNameThirdArg(t *testing.T) {
	o := newTestOptions(t, writeTestKubeconfig(t, ""))
	as := "jane"
	o.ConfigFlags.Impersonate = &as
	if err := o.Complete([]string{"get", "secrets", "db-password"}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if o.ResourceName != "db-password" {
		t.Errorf("ResourceName = %q, want \"db-password\"", o.ResourceName)
	}
	req := o.ToPermissionRequest()
	if req.ResourceName != "db-password" {
		t.Errorf("request.ResourceName = %q, want \"db-password\"", req.ResourceName)
	}
}

func TestComplete_AsGroups(t *testing.T) {
	o := newTestOptions(t, writeTestKubeconfig(t, ""))
	as := "jane"
	groups := []string{"devs", "ops"}
	o.ConfigFlags.Impersonate = &as
	o.ConfigFlags.ImpersonateGroup = &groups
	if err := o.Complete([]string{"get", "pods"}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if len(o.AsGroups) != 2 || o.AsGroups[0] != "devs" {
		t.Errorf("AsGroups = %v, want [devs ops]", o.AsGroups)
	}
}

func TestComplete_TooManyArgs(t *testing.T) {
	o := newTestOptions(t, writeTestKubeconfig(t, ""))
	as := "jane"
	o.ConfigFlags.Impersonate = &as
	if err := o.Complete([]string{"get", "secrets", "name", "extra"}); err == nil {
		t.Fatal("expected error for 4 args")
	}
}

func TestComplete_NameWithNonResourceURL(t *testing.T) {
	o := newTestOptions(t, writeTestKubeconfig(t, ""))
	as := "jane"
	o.ConfigFlags.Impersonate = &as
	if err := o.Complete([]string{"get", "/healthz", "name"}); err == nil {
		t.Fatal("expected error combining a resource name with a non-resource URL")
	}
}

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

func TestParseResource_SubresourceFlagConflict(t *testing.T) {
	o := newTestOptions(t, writeTestKubeconfig(t, ""))
	o.Subresource = "log"
	if err := o.parseResource("pods/exec"); err == nil {
		t.Fatal("expected conflict error combining pods/exec with --subresource")
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
		exec *clientcmdapi.ExecConfig
		want bool
	}{
		{
			name: "aws eks get-token",
			exec: &clientcmdapi.ExecConfig{Command: "aws", Args: []string{"eks", "get-token", "--cluster-name", "c"}},
			want: true,
		},
		{
			name: "aws-iam-authenticator",
			exec: &clientcmdapi.ExecConfig{Command: "aws-iam-authenticator", Args: []string{"token", "-i", "c"}},
			want: true,
		},
		{
			name: "absolute path to aws",
			exec: &clientcmdapi.ExecConfig{Command: "/usr/local/bin/aws", Args: []string{"eks", "get-token"}},
			want: true,
		},
		{
			name: "aws sts (not eks get-token)",
			exec: &clientcmdapi.ExecConfig{Command: "aws", Args: []string{"sts", "get-caller-identity"}},
			want: false,
		},
		{
			name: "gcloud auth plugin",
			exec: &clientcmdapi.ExecConfig{Command: "gke-gcloud-auth-plugin"},
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

func TestConvertRoleToAssumedRoleArn(t *testing.T) {
	tests := []struct {
		name            string
		roleArn         string
		fallbackAccount string
		sessionName     string
		want            string
	}{
		{
			name:            "cross-account role uses role account",
			roleArn:         "arn:aws:iam::222:role/Admin",
			fallbackAccount: "111",
			want:            "arn:aws:sts::222:assumed-role/Admin",
		},
		{
			name:            "govcloud partition preserved",
			roleArn:         "arn:aws-us-gov:iam::222:role/Admin",
			fallbackAccount: "111",
			want:            "arn:aws-us-gov:sts::222:assumed-role/Admin",
		},
		{
			name:            "session name appended",
			roleArn:         "arn:aws:iam::222:role/Admin",
			fallbackAccount: "111",
			sessionName:     "EKSGetTokenAuth",
			want:            "arn:aws:sts::222:assumed-role/Admin/EKSGetTokenAuth",
		},
		{
			name:            "role with path keeps only role name",
			roleArn:         "arn:aws:iam::222:role/team/Admin",
			fallbackAccount: "111",
			want:            "arn:aws:sts::222:assumed-role/Admin",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := convertRoleToAssumedRoleArn(tt.roleArn, tt.fallbackAccount, tt.sessionName); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestInjectAWSProfile(t *testing.T) {
	awsExec := func(args []string, env []clientcmdapi.ExecEnvVar) *rest.Config {
		return &rest.Config{ExecProvider: &clientcmdapi.ExecConfig{
			Command: "aws",
			Args:    args,
			Env:     env,
		}}
	}

	t.Run("replaces existing --profile arg", func(t *testing.T) {
		cfg := awsExec([]string{"eks", "get-token", "--cluster-name", "c", "--profile", "old"}, nil)
		injectAWSProfile(cfg, "new")
		if cfg.ExecProvider.Args[4] != "--profile" || cfg.ExecProvider.Args[5] != "new" {
			t.Errorf("args = %v", cfg.ExecProvider.Args)
		}
	})

	t.Run("sets AWS_PROFILE env when no arg", func(t *testing.T) {
		cfg := awsExec([]string{"eks", "get-token", "--cluster-name", "c"}, nil)
		injectAWSProfile(cfg, "new")
		found := false
		for _, e := range cfg.ExecProvider.Env {
			if e.Name == "AWS_PROFILE" && e.Value == "new" {
				found = true
			}
		}
		if !found {
			t.Errorf("AWS_PROFILE not injected: %+v", cfg.ExecProvider.Env)
		}
	})

	t.Run("ignores non-AWS exec plugins", func(t *testing.T) {
		cfg := &rest.Config{ExecProvider: &clientcmdapi.ExecConfig{Command: "gke-gcloud-auth-plugin"}}
		injectAWSProfile(cfg, "new")
		if len(cfg.ExecProvider.Env) != 0 {
			t.Errorf("must not touch non-AWS plugins: %+v", cfg.ExecProvider.Env)
		}
	})

	t.Run("ignores nil exec provider", func(t *testing.T) {
		injectAWSProfile(&rest.Config{}, "new") // must not panic
	})
}

func TestFindResourceMatches(t *testing.T) {
	lists := []*metav1.APIResourceList{
		{
			GroupVersion: "v1",
			APIResources: []metav1.APIResource{
				{Name: "pods", Namespaced: true},
				{Name: "nodes", Namespaced: false},
				{Name: "pods/log", Namespaced: true},
			},
		},
		{
			GroupVersion: "apps/v1",
			APIResources: []metav1.APIResource{
				{Name: "deployments", Namespaced: true},
			},
		},
	}

	if m := findResourceMatches(lists, "nodes"); len(m) != 1 || m[0].namespaced || m[0].group != "" {
		t.Errorf("nodes: %+v", m)
	}
	if m := findResourceMatches(lists, "deployments"); len(m) != 1 || !m[0].namespaced || m[0].group != "apps" {
		t.Errorf("deployments: %+v", m)
	}
	if m := findResourceMatches(lists, "pods/log"); len(m) != 0 {
		t.Errorf("subresources must be skipped: %+v", m)
	}
	if m := findResourceMatches(lists, "widgets"); len(m) != 0 {
		t.Errorf("unknown resource: %+v", m)
	}
}
