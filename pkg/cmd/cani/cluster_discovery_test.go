package cani

import (
	"testing"

	"k8s.io/client-go/tools/clientcmd/api"
)

func TestParseEKSClusterARN(t *testing.T) {
	tests := []struct {
		name, in             string
		wantName, wantRegion string
		wantOK               bool
	}{
		{"standard", "arn:aws:eks:us-east-1:123456789012:cluster/my-cluster", "my-cluster", "us-east-1", true},
		{"govcloud", "arn:aws-us-gov:eks:us-gov-west-1:123456789012:cluster/g", "g", "us-gov-west-1", true},
		{"hyphenated name", "arn:aws:eks:eu-west-2:111122223333:cluster/prod-eu-2", "prod-eu-2", "eu-west-2", true},
		{"non-arn context", "minikube", "", "", false},
		{"missing cluster suffix", "arn:aws:eks:us-east-1:123456789012:nodegroup/x", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, r, ok := parseEKSClusterARN(tt.in)
			if ok != tt.wantOK || n != tt.wantName || r != tt.wantRegion {
				t.Fatalf("parseEKSClusterARN(%q) = (%q,%q,%v), want (%q,%q,%v)",
					tt.in, n, r, ok, tt.wantName, tt.wantRegion, tt.wantOK)
			}
		})
	}
}

func TestExtractRegionFromAPIServerURL(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"https://ABC123.gr7.us-east-1.eks.amazonaws.com", "us-east-1"},
		{"https://D34F.yl4.eu-central-1.eks.amazonaws.com", "eu-central-1"},
		{"https://kubernetes.docker.internal:6443", ""},
		{"", ""},
	}
	for _, tt := range tests {
		got := extractRegionFromAPIServerURL(tt.in)
		if got != tt.want {
			t.Errorf("extractRegionFromAPIServerURL(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestExtractClusterNameFromExecArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"aws eks get-token --cluster-name", []string{"--region", "us-east-1", "eks", "get-token", "--cluster-name", "prod"}, "prod"},
		{"aws-iam-authenticator -i", []string{"token", "-i", "my-cluster"}, "my-cluster"},
		{"--cluster-name= form", []string{"--cluster-name=foo"}, "foo"},
		{"--cluster-id= form", []string{"--cluster-id=bar"}, "bar"},
		{"missing", []string{"token", "--region", "us-east-1"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractClusterNameFromExecArgs(tt.args); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractRegionFromExecEnv(t *testing.T) {
	env := []api.ExecEnvVar{
		{Name: "OTHER", Value: "x"},
		{Name: "AWS_REGION", Value: "us-west-2"},
	}
	if got := extractRegionFromExecEnv(env); got != "us-west-2" {
		t.Errorf("got %q, want us-west-2", got)
	}
	envDefault := []api.ExecEnvVar{{Name: "AWS_DEFAULT_REGION", Value: "ap-south-1"}}
	if got := extractRegionFromExecEnv(envDefault); got != "ap-south-1" {
		t.Errorf("got %q, want ap-south-1", got)
	}
	if got := extractRegionFromExecEnv(nil); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestDeriveClusterIdentity(t *testing.T) {
	tests := []struct {
		name        string
		ctxName     string
		clusters    map[string]*api.Cluster
		contexts    map[string]*api.Context
		authInfos   map[string]*api.AuthInfo
		wantOK      bool
		wantCluster string
		wantRegion  string
	}{
		{
			name:    "context name is EKS ARN",
			ctxName: "arn:aws:eks:us-east-1:123456789012:cluster/prod",
			contexts: map[string]*api.Context{
				"arn:aws:eks:us-east-1:123456789012:cluster/prod": {Cluster: "c", AuthInfo: "a"},
			},
			clusters:    map[string]*api.Cluster{"c": {Server: "https://x.gr7.us-east-1.eks.amazonaws.com"}},
			authInfos:   map[string]*api.AuthInfo{"a": {}},
			wantOK:      true,
			wantCluster: "prod",
			wantRegion:  "us-east-1",
		},
		{
			name:    "exec args supply cluster, server URL supplies region",
			ctxName: "my-context",
			contexts: map[string]*api.Context{
				"my-context": {Cluster: "c", AuthInfo: "a"},
			},
			clusters: map[string]*api.Cluster{"c": {Server: "https://abc.gr7.eu-west-2.eks.amazonaws.com"}},
			authInfos: map[string]*api.AuthInfo{"a": {Exec: &api.ExecConfig{
				Command: "aws",
				Args:    []string{"eks", "get-token", "--cluster-name", "staging"},
			}}},
			wantOK:      true,
			wantCluster: "staging",
			wantRegion:  "eu-west-2",
		},
		{
			name:    "exec env supplies region when server URL is non-EKS",
			ctxName: "ctx",
			contexts: map[string]*api.Context{
				"ctx": {Cluster: "c", AuthInfo: "a"},
			},
			clusters: map[string]*api.Cluster{"c": {Server: "https://example.com"}},
			authInfos: map[string]*api.AuthInfo{"a": {Exec: &api.ExecConfig{
				Args: []string{"--cluster-name", "k"},
				Env:  []api.ExecEnvVar{{Name: "AWS_REGION", Value: "ap-northeast-1"}},
			}}},
			wantOK:      true,
			wantCluster: "k",
			wantRegion:  "ap-northeast-1",
		},
		{
			name:    "no cluster name derivable",
			ctxName: "minikube",
			contexts: map[string]*api.Context{
				"minikube": {Cluster: "minikube", AuthInfo: "minikube"},
			},
			clusters:  map[string]*api.Cluster{"minikube": {Server: "https://kubernetes.docker.internal:6443"}},
			authInfos: map[string]*api.AuthInfo{"minikube": {}},
			wantOK:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := api.Config{Contexts: tt.contexts, Clusters: tt.clusters, AuthInfos: tt.authInfos}
			id, ok := DeriveClusterIdentity(cfg, tt.ctxName)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v (id=%+v)", ok, tt.wantOK, id)
			}
			if !ok {
				return
			}
			if id.ClusterName != tt.wantCluster || id.Region != tt.wantRegion {
				t.Errorf("got (%q,%q), want (%q,%q)", id.ClusterName, id.Region, tt.wantCluster, tt.wantRegion)
			}
		})
	}
}
