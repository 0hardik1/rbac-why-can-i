package output

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/hardik/kubectl-rbac-why/pkg/rbac"
)

func TestResolveColor(t *testing.T) {
	t.Run("never is always off", func(t *testing.T) {
		if ResolveColor("never", os.Stdout) {
			t.Error("never should disable color")
		}
	})
	t.Run("always is on even for a non-terminal", func(t *testing.T) {
		if !ResolveColor("always", &bytes.Buffer{}) {
			t.Error("always should enable color")
		}
	})
	t.Run("auto is off for a non-terminal writer", func(t *testing.T) {
		if ResolveColor("auto", &bytes.Buffer{}) {
			t.Error("auto should disable color for a non-terminal")
		}
	})
	t.Run("auto respects NO_COLOR", func(t *testing.T) {
		t.Setenv("NO_COLOR", "1")
		if ResolveColor("auto", &bytes.Buffer{}) {
			t.Error("auto with NO_COLOR set should disable color")
		}
	})
}

func TestColorize(t *testing.T) {
	if got := colorize(false, colorRed, "x"); got != "x" {
		t.Errorf("disabled colorize should return plain text, got %q", got)
	}
	if got := colorize(true, colorGreen, "ok"); got != colorGreen+"ok"+colorReset {
		t.Errorf("enabled colorize = %q", got)
	}
}

func TestTextPrinterColor(t *testing.T) {
	result := &rbac.PermissionResult{
		Allowed: true,
		Subject: rbac.Subject{Kind: "User", Name: "alice"},
		Request: rbac.PermissionRequest{Verb: "get", Resource: "pods"},
		Grants: []rbac.PermissionGrant{{
			Binding: rbac.BindingInfo{Kind: "ClusterRoleBinding", Name: "b"},
			Role:    rbac.RoleInfo{Kind: "ClusterRole", Name: "r"},
			Scope:   rbac.ScopeClusterWide,
		}},
	}

	var colored bytes.Buffer
	if err := (&TextPrinter{Color: true}).Print(&colored, result, nil); err != nil {
		t.Fatalf("Print error: %v", err)
	}
	if !strings.Contains(colored.String(), colorGreen+"ALLOWED"+colorReset) {
		t.Errorf("expected green ALLOWED, got: %q", colored.String())
	}

	var plain bytes.Buffer
	if err := (&TextPrinter{Color: false}).Print(&plain, result, nil); err != nil {
		t.Fatalf("Print error: %v", err)
	}
	if strings.Contains(plain.String(), "\033[") {
		t.Errorf("plain output should contain no ANSI codes: %q", plain.String())
	}
}
