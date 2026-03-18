package registry

import "testing"

func TestParseBearerChallenge(t *testing.T) {
	t.Run("valid challenge", func(t *testing.T) {
		header := `Bearer realm="https://scc.suse.com/api/registry/authorize",service="SUSE Linux Docker Registry",scope="repository:rancher/hardened-traefik:pull"`
		challenge, err := parseBearerChallenge(header)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if challenge.Realm != "https://scc.suse.com/api/registry/authorize" {
			t.Fatalf("unexpected realm: %q", challenge.Realm)
		}

		if challenge.Service != "SUSE Linux Docker Registry" {
			t.Fatalf("unexpected service: %q", challenge.Service)
		}

		if challenge.Scope != "repository:rancher/hardened-traefik:pull" {
			t.Fatalf("unexpected scope: %q", challenge.Scope)
		}
	})

	t.Run("missing realm", func(t *testing.T) {
		_, err := parseBearerChallenge(`Bearer service="svc"`)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
	})
}

func TestParseNextPageURL(t *testing.T) {
	t.Run("absolute next link", func(t *testing.T) {
		next, err := parseNextPageURL(`<https://registry.rancher.com/v2/rancher/hardened-traefik/tags/list?n=100&last=abc>; rel="next"`, "https://registry.rancher.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expected := "https://registry.rancher.com/v2/rancher/hardened-traefik/tags/list?n=100&last=abc"
		if next != expected {
			t.Fatalf("unexpected next URL: %q", next)
		}
	})

	t.Run("relative next link", func(t *testing.T) {
		next, err := parseNextPageURL(`</v2/rancher/hardened-traefik/tags/list?n=100&last=abc>; rel="next"`, "https://registry.rancher.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expected := "https://registry.rancher.com/v2/rancher/hardened-traefik/tags/list?n=100&last=abc"
		if next != expected {
			t.Fatalf("unexpected next URL: %q", next)
		}
	})

	t.Run("empty header", func(t *testing.T) {
		next, err := parseNextPageURL("", "https://registry.rancher.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if next != "" {
			t.Fatalf("expected empty next URL, got %q", next)
		}
	})
}

func TestResolveRegistryBaseURL(t *testing.T) {
	t.Run("default host", func(t *testing.T) {
		t.Setenv(registryEnv, "")
		baseURL, err := resolveRegistryBaseURL()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if baseURL != "https://"+defaultRegistryHost {
			t.Fatalf("unexpected base URL: %q", baseURL)
		}
	})

	t.Run("host without scheme", func(t *testing.T) {
		t.Setenv(registryEnv, "mirror.local:5000")
		baseURL, err := resolveRegistryBaseURL()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if baseURL != "https://mirror.local:5000" {
			t.Fatalf("unexpected base URL: %q", baseURL)
		}
	})

	t.Run("value with scheme and path", func(t *testing.T) {
		t.Setenv(registryEnv, "http://registry.local/proxy/")
		baseURL, err := resolveRegistryBaseURL()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if baseURL != "http://registry.local/proxy" {
			t.Fatalf("unexpected base URL: %q", baseURL)
		}
	})

	t.Run("invalid scheme", func(t *testing.T) {
		t.Setenv(registryEnv, "ftp://registry.local")
		_, err := resolveRegistryBaseURL()
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
	})

	t.Run("missing host", func(t *testing.T) {
		t.Setenv(registryEnv, "https://")
		_, err := resolveRegistryBaseURL()
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
	})
}

func TestNormalizeRepository(t *testing.T) {
	t.Run("valid repository", func(t *testing.T) {
		repository, err := normalizeRepository("rancher/hardened-traefik")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if repository != "rancher/hardened-traefik" {
			t.Fatalf("unexpected repository: %q", repository)
		}
	})

	t.Run("invalid repository", func(t *testing.T) {
		_, err := normalizeRepository("hardened-traefik")
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
	})
}
