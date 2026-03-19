package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/manuelbuil/PoCs/2026/rke2-patcher/internal/registry"
)

func TestParseImagePatchOptions(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		expected     imagePatchOptions
		errContains  string
		errContains2 string
	}{
		{
			name:     "no options",
			args:     nil,
			expected: imagePatchOptions{},
		},
		{
			name: "dry run and revert",
			args: []string{"--dry-run", "--revert"},
			expected: imagePatchOptions{
				DryRun: true,
				Revert: true,
			},
		},
		{
			name:         "unsupported option",
			args:         []string{"--unknown"},
			errContains:  "unsupported image-patch option",
			errContains2: "--unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options, err := parseImagePatchOptions(tt.args)
			if tt.errContains != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.errContains)
				}
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Fatalf("expected error containing %q, got %q", tt.errContains, err.Error())
				}
				if tt.errContains2 != "" && !strings.Contains(err.Error(), tt.errContains2) {
					t.Fatalf("expected error containing %q, got %q", tt.errContains2, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !reflect.DeepEqual(options, tt.expected) {
				t.Fatalf("unexpected options: %#v", options)
			}
		})
	}
}

func TestEnsureManifestsDirectoryExists(t *testing.T) {
	t.Run("existing directory", func(t *testing.T) {
		tempDir := t.TempDir()
		filePath := filepath.Join(tempDir, "manifest.yaml")

		if err := ensureManifestsDirectoryExists(filePath); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("missing directory", func(t *testing.T) {
		tempDir := t.TempDir()
		filePath := filepath.Join(tempDir, "missing", "manifest.yaml")

		err := ensureManifestsDirectoryExists(filePath)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "does not exist") {
			t.Fatalf("expected does not exist error, got %q", err.Error())
		}
		if !strings.Contains(err.Error(), "RKE2_PATCHER_DATA_DIR") {
			t.Fatalf("expected suggestion to use RKE2_PATCHER_DATA_DIR, got %q", err.Error())
		}
	})

	t.Run("manifests path is not a directory", func(t *testing.T) {
		tempDir := t.TempDir()
		notDir := filepath.Join(tempDir, "not-a-dir")
		if err := os.WriteFile(notDir, []byte("x"), 0644); err != nil {
			t.Fatalf("failed writing file: %v", err)
		}

		filePath := filepath.Join(notDir, "manifest.yaml")
		err := ensureManifestsDirectoryExists(filePath)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "is not a directory") {
			t.Fatalf("expected not a directory error, got %q", err.Error())
		}
		if !strings.Contains(err.Error(), "RKE2_PATCHER_DATA_DIR") {
			t.Fatalf("expected suggestion to use RKE2_PATCHER_DATA_DIR, got %q", err.Error())
		}
	})
}

func TestParseComparableTag(t *testing.T) {
	t.Run("version build tag", func(t *testing.T) {
		tag, ok := parseComparableTag("v1.14.1-build20260206")
		if !ok {
			t.Fatalf("expected tag to be parseable")
		}

		if tag.Major != 1 || tag.Minor != 14 || tag.Patch != 1 || tag.Build != 20260206 {
			t.Fatalf("unexpected parsed tag: %#v", tag)
		}
	})

	t.Run("lts build tag", func(t *testing.T) {
		tag, ok := parseComparableTag("v1.12.0-lts1-build20250210")
		if !ok {
			t.Fatalf("expected lts tag to be parseable")
		}

		if tag.Flavor != "lts1" {
			t.Fatalf("unexpected flavor: %q", tag.Flavor)
		}
	})

	t.Run("signature tag excluded", func(t *testing.T) {
		if _, ok := parseComparableTag("sha256-1234.sig"); ok {
			t.Fatalf("expected signature tag to be excluded")
		}
	})
}

func TestSelectTagsForCVEListing_OrderedAndFiltered(t *testing.T) {
	tags := []registry.Tag{
		{Name: "sha256-063f303c.att"},
		{Name: "sha256-063f303c.sig"},
		{Name: "v1.10.1-build20230406"},
		{Name: "v1.12.4-build20251015"},
		{Name: "v1.14.1-build20260203"},
		{Name: "v1.14.1-build20260206"},
		{Name: "v1.14.2-build20260309"},
	}

	ordered, previous := selectTagsForCVEListing(tags, "v1.14.1-build20260206")

	expectedOrdered := []string{
		"v1.14.2-build20260309",
		"v1.14.1-build20260206",
		"v1.14.1-build20260203",
	}

	if !reflect.DeepEqual(ordered, expectedOrdered) {
		t.Fatalf("unexpected ordered tags: %#v", ordered)
	}

	if previous != "v1.14.1-build20260203" {
		t.Fatalf("unexpected previous tag: %q", previous)
	}
}

func TestOrderedComparableTags(t *testing.T) {
	tags := []registry.Tag{
		{Name: "v1.14.1-build20260206"},
		{Name: "v1.14.2-build20260309"},
		{Name: "v1.14.1-build20260203"},
		{Name: "sha256-1234.att"},
	}

	ordered := orderedComparableTags(tags)
	expected := []string{
		"v1.14.2-build20260309",
		"v1.14.1-build20260206",
		"v1.14.1-build20260203",
	}

	if !reflect.DeepEqual(ordered, expected) {
		t.Fatalf("unexpected ordered tags: %#v", ordered)
	}
}

func TestResolvePatchTargetTag_RejectsNewerMinorUpgrade(t *testing.T) {
	repository := "rancher/hardened-traefik"
	server := newTagsServer(t, repository, []string{
		"v1.14.1-build20260206",
		"v1.15.0-build20260301",
	})
	t.Setenv("RKE2_PATCHER_REGISTRY", server.URL)

	_, err := resolvePatchTargetTag(repository, "v1.14.1-build20260206", false)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	if !strings.Contains(err.Error(), "moving to a newer minor release is not supported") {
		t.Fatalf("expected minor-upgrade guard error, got %q", err.Error())
	}
}

func TestResolvePatchTargetTag_AllowsSameMinorUpgrade(t *testing.T) {
	repository := "rancher/hardened-traefik"
	server := newTagsServer(t, repository, []string{
		"v1.14.1-build20260206",
		"v1.14.2-build20260309",
	})
	t.Setenv("RKE2_PATCHER_REGISTRY", server.URL)

	targetTag, err := resolvePatchTargetTag(repository, "v1.14.1-build20260206", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if targetTag != "v1.14.2-build20260309" {
		t.Fatalf("unexpected target tag: %q", targetTag)
	}
}

func newTagsServer(t *testing.T, repository string, tags []string) *httptest.Server {
	t.Helper()

	path := fmt.Sprintf("/v2/%s/tags/list", repository)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"tags":["%s"]}`, strings.Join(tags, `","`))
	})

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	return server
}

func TestEvaluatePatchLimit_OnlyOneForwardPatchPerComponentAndClusterVersion(t *testing.T) {
	t.Setenv(patchLimitCacheDirEnv, t.TempDir())

	originalClusterVersionResolver := clusterVersionResolver
	clusterVersionResolver = func() (string, error) {
		return "v1.35.2+rke2r1", nil
	}
	t.Cleanup(func() {
		clusterVersionResolver = originalClusterVersionResolver
	})

	decision, err := evaluatePatchLimit("rke2-traefik", "v3.6.7-build20260301", "v3.6.8-build20260302", false)
	if err != nil {
		t.Fatalf("unexpected error during first patch evaluation: %v", err)
	}

	if !decision.ShouldPersist {
		t.Fatalf("expected first patch decision to require persistence")
	}

	if err := persistPatchLimitDecision(decision); err != nil {
		t.Fatalf("unexpected persistence error: %v", err)
	}

	_, err = evaluatePatchLimit("rke2-traefik", "v3.6.8-build20260302", "v3.6.9-build20260303", false)
	if err == nil {
		t.Fatalf("expected second forward patch to be rejected")
	}

	if !strings.Contains(err.Error(), "already patched once") {
		t.Fatalf("expected already-patched-once error, got %q", err.Error())
	}

	if !strings.Contains(err.Error(), "upgrade RKE2 to patch again") {
		t.Fatalf("expected upgrade RKE2 guidance, got %q", err.Error())
	}
}

func TestEvaluatePatchLimit_AllowsForwardPatchAfterRKE2Upgrade(t *testing.T) {
	t.Setenv(patchLimitCacheDirEnv, t.TempDir())

	clusterVersion := "v1.35.2+rke2r1"
	originalClusterVersionResolver := clusterVersionResolver
	clusterVersionResolver = func() (string, error) {
		return clusterVersion, nil
	}
	t.Cleanup(func() {
		clusterVersionResolver = originalClusterVersionResolver
	})

	firstDecision, err := evaluatePatchLimit("rke2-traefik", "v3.6.7-build20260301", "v3.6.8-build20260302", false)
	if err != nil {
		t.Fatalf("unexpected first patch evaluation error: %v", err)
	}
	if err := persistPatchLimitDecision(firstDecision); err != nil {
		t.Fatalf("unexpected first persistence error: %v", err)
	}

	clusterVersion = "v1.36.0+rke2r1"
	secondDecision, err := evaluatePatchLimit("rke2-traefik", "v3.6.8-build20260302", "v3.6.9-build20260303", false)
	if err != nil {
		t.Fatalf("expected patch to be allowed after cluster version change, got %v", err)
	}

	if !secondDecision.ShouldPersist {
		t.Fatalf("expected second patch decision to require persistence")
	}
}

func TestEvaluatePatchLimit_RevertDoesNotCreateOrRequireState(t *testing.T) {
	t.Setenv(patchLimitCacheDirEnv, t.TempDir())

	originalClusterVersionResolver := clusterVersionResolver
	clusterVersionResolver = func() (string, error) {
		return "v1.35.2+rke2r1", nil
	}
	t.Cleanup(func() {
		clusterVersionResolver = originalClusterVersionResolver
	})

	decision, err := evaluatePatchLimit("rke2-traefik", "v3.6.8-build20260302", "v3.6.7-build20260301", true)
	if err != nil {
		t.Fatalf("expected revert evaluation to succeed, got %v", err)
	}

	if decision.ShouldPersist {
		t.Fatalf("expected revert decision to skip persistence")
	}
}
