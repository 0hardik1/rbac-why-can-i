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

func TestMultipleGrants(t *testing.T) {
	// test-sa should have multiple paths to some permissions
	// (view ClusterRole via RoleBinding + node-reader via ClusterRoleBinding)
	out, err := runRbacWhy(
		"can-i",
		"--as", "system:serviceaccount:test-ns:test-sa",
		"get", "configmaps",
		"-n", testNS,
		"-o", "json",
	)
	if err != nil {
		t.Fatalf("command failed: %v", err)
	}

	var result output.JSONOutput
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// If granted, verify we get the expected structure
	if result.Allowed && len(result.Grants) > 0 {
		grant := result.Grants[0]
		if grant.Binding.Kind == "" {
			t.Errorf("expected binding kind to be set")
		}
		if grant.Role.Kind == "" {
			t.Errorf("expected role kind to be set")
		}
	}
}
