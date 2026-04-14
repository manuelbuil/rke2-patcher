package components

import (
	"strings"
	"testing"
)

func TestSupportedReturnsRKE2PrefixedNames(t *testing.T) {
	supported := Supported()
	if len(supported) == 0 {
		t.Fatal("expected supported components")
	}

	for _, name := range supported {
		if !strings.HasPrefix(name, "rke2-") {
			t.Fatalf("expected rke2-prefixed component name, got %q", name)
		}
	}
}

func TestResolveAcceptsPrefixedAndLegacyNames(t *testing.T) {
	legacy, err := Resolve("metrics-server")
	if err != nil {
		t.Fatalf("resolve legacy name failed: %v", err)
	}

	prefixed, err := Resolve("rke2-metrics-server")
	if err != nil {
		t.Fatalf("resolve prefixed name failed: %v", err)
	}

	if legacy != prefixed {
		t.Fatalf("expected same component for legacy and prefixed names")
	}
}

func TestCLINameReturnsPrefixedName(t *testing.T) {
	if got := CLIName("metrics-server"); got != "rke2-metrics-server" {
		t.Fatalf("expected rke2-metrics-server, got %q", got)
	}

	if got := CLIName("rke2-metrics-server"); got != "rke2-metrics-server" {
		t.Fatalf("expected rke2-metrics-server, got %q", got)
	}
}
