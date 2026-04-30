package cani

import (
	"regexp"
	"strings"

	"k8s.io/client-go/tools/clientcmd/api"
)

// ClusterIdentity holds the EKS cluster name + region needed for SDK calls.
type ClusterIdentity struct {
	ClusterName string
	Region      string
}

// eksClusterARNRe matches the ARN format that `aws eks update-kubeconfig`
// writes as the kubeconfig context name by default:
//
//	arn:aws:eks:<region>:<account>:cluster/<name>
var eksClusterARNRe = regexp.MustCompile(`^arn:aws[a-z0-9-]*:eks:([a-z0-9-]+):[0-9]+:cluster/(.+)$`)

// eksAPIServerRe matches an EKS API server URL and captures the region.
// Standard form: https://<id>.gr7.<region>.eks.amazonaws.com
// (gr7 is a routing prefix that varies; we accept any subdomain segment.)
var eksAPIServerRe = regexp.MustCompile(`\.([a-z0-9-]+)\.eks\.amazonaws\.com`)

// DeriveClusterIdentity extracts the EKS cluster name and region from a
// kubeconfig context. Returns (nil, false) if no EKS cluster identity could
// be derived from the context (the caller should treat this as "not on EKS"
// or "not enough info" and skip EKS API calls).
//
// Strategy, in order:
//  1. Parse the context name as an EKS cluster ARN.
//  2. Extract the region from the cluster server URL.
//  3. Fall back to scanning exec args/env for cluster name + region.
//
// All sources contribute independently — e.g., context name may give the
// cluster name while exec env supplies the region.
func DeriveClusterIdentity(rawConfig api.Config, contextName string) (*ClusterIdentity, bool) {
	id := &ClusterIdentity{}

	// 1. Context name shaped as an EKS cluster ARN.
	if name, region, ok := parseEKSClusterARN(contextName); ok {
		id.ClusterName = name
		id.Region = region
	}

	currentContext, ok := rawConfig.Contexts[contextName]
	if !ok || currentContext == nil {
		if id.ClusterName != "" && id.Region != "" {
			return id, true
		}
		return nil, false
	}

	// 2. Region from cluster server URL.
	if id.Region == "" {
		if cluster, ok := rawConfig.Clusters[currentContext.Cluster]; ok && cluster != nil {
			id.Region = extractRegionFromAPIServerURL(cluster.Server)
		}
	}

	// 3. Exec block fallbacks.
	if authInfo, ok := rawConfig.AuthInfos[currentContext.AuthInfo]; ok && authInfo != nil && authInfo.Exec != nil {
		if id.ClusterName == "" {
			id.ClusterName = extractClusterNameFromExecArgs(authInfo.Exec.Args)
		}
		if id.Region == "" {
			id.Region = extractRegionFromExecEnv(authInfo.Exec.Env)
		}
	}

	if id.ClusterName == "" {
		return nil, false
	}
	return id, true
}

// parseEKSClusterARN parses arn:aws:eks:<region>:<account>:cluster/<name>.
func parseEKSClusterARN(s string) (clusterName, region string, ok bool) {
	m := eksClusterARNRe.FindStringSubmatch(s)
	if m == nil {
		return "", "", false
	}
	return m[2], m[1], true
}

// extractRegionFromAPIServerURL parses the region segment out of an EKS API
// server URL. Returns "" if the URL doesn't look like an EKS endpoint.
func extractRegionFromAPIServerURL(serverURL string) string {
	m := eksAPIServerRe.FindStringSubmatch(serverURL)
	if m == nil {
		return ""
	}
	return m[1]
}

// extractClusterNameFromExecArgs walks an exec block's args for cluster-name
// flags written by `aws eks get-token` (--cluster-name) or by
// aws-iam-authenticator (-i / --cluster-id).
func extractClusterNameFromExecArgs(args []string) string {
	for i, arg := range args {
		switch arg {
		case "--cluster-name", "-i", "--cluster-id":
			if i+1 < len(args) {
				return args[i+1]
			}
		}
		for _, prefix := range []string{"--cluster-name=", "--cluster-id=", "-i="} {
			if strings.HasPrefix(arg, prefix) {
				return strings.TrimPrefix(arg, prefix)
			}
		}
	}
	return ""
}

// extractRegionFromExecEnv walks the exec block's env for AWS_REGION /
// AWS_DEFAULT_REGION.
func extractRegionFromExecEnv(env []api.ExecEnvVar) string {
	for _, e := range env {
		if e.Name == "AWS_REGION" || e.Name == "AWS_DEFAULT_REGION" {
			if e.Value != "" {
				return e.Value
			}
		}
	}
	return ""
}
