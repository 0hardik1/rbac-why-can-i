package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardik/kubectl-rbac-why/pkg/output"
)

var (
	binaryPath string
	testNS     = "test-ns"
)

func TestMain(m *testing.M) {
	// Find the binary
	binaryPath = os.Getenv("RBAC_WHY_BINARY")
	if binaryPath == "" {
		// Try to find it relative to the test
		binaryPath = filepath.Join("..", "..", "bin", "kubectl-rbac_why")
	}

	// Check if we have a working kubernetes cluster
	if err := checkCluster(); err != nil {
		// Skip e2e tests if no cluster available
		os.Exit(0)
	}

	// Setup test resources
	if err := setupTestResources(); err != nil {
		panic("failed to setup test resources: " + err.Error())
	}

	code := m.Run()

	// Cleanup (optional - leave resources for debugging)
	// cleanupTestResources()

	os.Exit(code)
}

func checkCluster() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "kubectl", "cluster-info")
	return cmd.Run()
}

func setupTestResources() error {
	manifestPath := filepath.Join("testdata", "manifests", "rbac-fixtures.yaml")
	cmd := exec.Command("kubectl", "apply", "-f", manifestPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// nolint:unused // Kept for manual debugging/cleanup
func cleanupTestResources() error {
	manifestPath := filepath.Join("testdata", "manifests", "rbac-fixtures.yaml")
	cmd := exec.Command("kubectl", "delete", "-f", manifestPath, "--ignore-not-found")
	return cmd.Run()
}

func runRbacWhy(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binaryPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if stderr.Len() > 0 {
			return "", fmt.Errorf("%w: %s", err, stderr.String())
		}
		return "", err
	}

	return stdout.String(), nil
}

func TestCanI_ServiceAccountGetSecrets(t *testing.T) {
	out, err := runRbacWhy(
		"can-i",
		"--as", "system:serviceaccount:test-ns:test-sa",
		"get", "secrets",
		"-n", testNS,
	)
	if err != nil {
		t.Fatalf("command failed: %v", err)
	}

	// Should be ALLOWED
	if !strings.Contains(out, "ALLOWED") {
		t.Errorf("expected ALLOWED, got: %s", out)
	}

	// Should mention the RoleBinding
	if !strings.Contains(out, "RoleBinding") {
		t.Errorf("expected RoleBinding in output, got: %s", out)
	}

	// Should mention secret-reader role
	if !strings.Contains(out, "secret-reader") {
		t.Errorf("expected secret-reader role in output, got: %s", out)
	}
}

func TestCanI_ServiceAccountDenied(t *testing.T) {
	out, err := runRbacWhy(
		"can-i",
		"--as", "system:serviceaccount:test-ns:test-sa",
		"delete", "secrets",
		"-n", testNS,
	)
	if err != nil {
		t.Fatalf("command failed: %v", err)
	}

	// Should be DENIED (test-sa only has get/list/watch on secrets)
	if !strings.Contains(out, "DENIED") {
		t.Errorf("expected DENIED, got: %s", out)
	}
}

func TestCanI_ClusterRoleBinding(t *testing.T) {
	out, err := runRbacWhy(
		"can-i",
		"--as", "system:serviceaccount:test-ns:test-sa",
		"list", "nodes",
	)
	if err != nil {
		t.Fatalf("command failed: %v", err)
	}

	// Should be ALLOWED via ClusterRoleBinding
	if !strings.Contains(out, "ALLOWED") {
		t.Errorf("expected ALLOWED, got: %s", out)
	}

	// Should mention ClusterRoleBinding
	if !strings.Contains(out, "ClusterRoleBinding") {
		t.Errorf("expected ClusterRoleBinding in output, got: %s", out)
	}

	// Should mention cluster-wide scope
	if !strings.Contains(out, "cluster-wide") {
		t.Errorf("expected cluster-wide scope in output, got: %s", out)
	}
}

func TestCanI_Subresource(t *testing.T) {
	out, err := runRbacWhy(
		"can-i",
		"--as", "system:serviceaccount:test-ns:admin-sa",
		"create", "pods/exec",
		"-n", testNS,
	)
	if err != nil {
		t.Fatalf("command failed: %v", err)
	}

	// admin-sa should be allowed to exec (via pod-manager role)
	if !strings.Contains(out, "ALLOWED") {
		t.Errorf("expected ALLOWED, got: %s", out)
	}
}

func TestCanI_JSONOutput(t *testing.T) {
	out, err := runRbacWhy(
		"can-i",
		"--as", "system:serviceaccount:test-ns:test-sa",
		"get", "secrets",
		"-n", testNS,
		"-o", "json",
	)
	if err != nil {
		t.Fatalf("command failed: %v", err)
	}

	// Should be valid JSON
	var result output.JSONOutput
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON output: %v\nOutput: %s", err, out)
	}

	if !result.Allowed {
		t.Errorf("expected allowed=true, got false")
	}

	if result.Subject.Kind != "ServiceAccount" {
		t.Errorf("expected subject kind ServiceAccount, got %s", result.Subject.Kind)
	}

	if len(result.Grants) == 0 {
		t.Errorf("expected at least one grant")
	}
}

func TestCanI_YAMLOutput(t *testing.T) {
	out, err := runRbacWhy(
		"can-i",
		"--as", "system:serviceaccount:test-ns:test-sa",
		"get", "secrets",
		"-n", testNS,
		"-o", "yaml",
	)
	if err != nil {
		t.Fatalf("command failed: %v", err)
	}

	// Should contain YAML-like content
	if !strings.Contains(out, "allowed:") {
		t.Errorf("expected YAML with 'allowed:' field, got: %s", out)
	}
}

func TestCanI_DotOutput(t *testing.T) {
	out, err := runRbacWhy(
		"can-i",
		"--as", "system:serviceaccount:test-ns:test-sa",
		"get", "secrets",
		"-n", testNS,
		"-o", "dot",
	)
	if err != nil {
		t.Fatalf("command failed: %v", err)
	}

	// Should contain DOT graph syntax
	if !strings.Contains(out, "digraph rbac") {
		t.Errorf("expected DOT graph, got: %s", out)
	}
}

func TestCanI_MermaidOutput(t *testing.T) {
	out, err := runRbacWhy(
		"can-i",
		"--as", "system:serviceaccount:test-ns:test-sa",
		"get", "secrets",
		"-n", testNS,
		"-o", "mermaid",
	)
	if err != nil {
		t.Fatalf("command failed: %v", err)
	}

	// Should contain Mermaid graph syntax
	if !strings.Contains(out, "graph LR") {
		t.Errorf("expected Mermaid graph, got: %s", out)
	}
}

func TestShowRisky(t *testing.T) {
	out, err := runRbacWhy(
		"can-i",
		"--as", "system:serviceaccount:test-ns:admin-sa",
		"--show-risky",
		"-n", testNS,
	)
	if err != nil {
		t.Fatalf("command failed: %v", err)
	}

	// admin-sa has risky permissions (secrets with *, pods/exec)
	if !strings.Contains(out, "risky") && !strings.Contains(out, "CRITICAL") {
		t.Errorf("expected risky permissions output, got: %s", out)
	}
}

func TestMultipleGrants_TwoRoles(t *testing.T) {
	// dual-grant-sa has the same permission (get configmaps) granted through:
	// 1. RoleBinding -> Role (configmap-reader-role)
	// 2. ClusterRoleBinding -> ClusterRole (test-configmap-reader-clusterrole)
	out, err := runRbacWhy(
		"can-i",
		"--as", "system:serviceaccount:test-ns:dual-grant-sa",
		"get", "configmaps",
		"-n", testNS,
		"-o", "json",
	)
	if err != nil {
		t.Fatalf("command failed: %v", err)
	}

	var result output.JSONOutput
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON: %v\nOutput: %s", err, out)
	}

	if !result.Allowed {
		t.Fatalf("expected permission to be allowed")
	}

	// Must have exactly 2 grants
	if len(result.Grants) != 2 {
		t.Errorf("expected 2 grants, got %d", len(result.Grants))
		for i, g := range result.Grants {
			t.Logf("Grant %d: %s/%s -> %s/%s", i, g.Binding.Kind, g.Binding.Name, g.Role.Kind, g.Role.Name)
		}
	}

	// Verify we have one from RoleBinding and one from ClusterRoleBinding
	var hasRoleBinding, hasClusterRoleBinding bool
	for _, grant := range result.Grants {
		if grant.Binding.Kind == "RoleBinding" && grant.Role.Kind == "Role" {
			hasRoleBinding = true
		}
		if grant.Binding.Kind == "ClusterRoleBinding" && grant.Role.Kind == "ClusterRole" {
			hasClusterRoleBinding = true
		}
	}

	if !hasRoleBinding {
		t.Errorf("expected a grant from RoleBinding -> Role")
	}
	if !hasClusterRoleBinding {
		t.Errorf("expected a grant from ClusterRoleBinding -> ClusterRole")
	}
}

func TestMultipleGrants_FourRoles(t *testing.T) {
	// quad-grant-sa has the same permission (get pods) granted through 4 paths:
	// 1. RoleBinding -> Role (pod-getter-role-1)
	// 2. RoleBinding -> Role (pod-getter-role-2)
	// 3. RoleBinding -> ClusterRole (test-pod-getter-clusterrole-1)
	// 4. ClusterRoleBinding -> ClusterRole (test-pod-getter-clusterrole-2)
	out, err := runRbacWhy(
		"can-i",
		"--as", "system:serviceaccount:test-ns:quad-grant-sa",
		"get", "pods",
		"-n", testNS,
		"-o", "json",
	)
	if err != nil {
		t.Fatalf("command failed: %v", err)
	}

	var result output.JSONOutput
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON: %v\nOutput: %s", err, out)
	}

	if !result.Allowed {
		t.Fatalf("expected permission to be allowed")
	}

	// Must have exactly 4 grants
	if len(result.Grants) != 4 {
		t.Errorf("expected 4 grants, got %d", len(result.Grants))
		for i, g := range result.Grants {
			t.Logf("Grant %d: %s/%s -> %s/%s", i, g.Binding.Kind, g.Binding.Name, g.Role.Kind, g.Role.Name)
		}
	}

	// Verify grant types
	var roleBindingToRole, roleBindingToClusterRole, clusterRoleBinding int
	for _, grant := range result.Grants {
		switch {
		case grant.Binding.Kind == "RoleBinding" && grant.Role.Kind == "Role":
			roleBindingToRole++
		case grant.Binding.Kind == "RoleBinding" && grant.Role.Kind == "ClusterRole":
			roleBindingToClusterRole++
		case grant.Binding.Kind == "ClusterRoleBinding":
			clusterRoleBinding++
		}
	}

	if roleBindingToRole != 2 {
		t.Errorf("expected 2 grants from RoleBinding -> Role, got %d", roleBindingToRole)
	}
	if roleBindingToClusterRole != 1 {
		t.Errorf("expected 1 grant from RoleBinding -> ClusterRole, got %d", roleBindingToClusterRole)
	}
	if clusterRoleBinding != 1 {
		t.Errorf("expected 1 grant from ClusterRoleBinding -> ClusterRole, got %d", clusterRoleBinding)
	}
}
