package cmd

import (
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/manuelbuil/rke2-patcher/internal/registry"
	cli "github.com/urfave/cli/v2"
)

func TestRunImageListCommandVerboseRequiresWithCVEs(t *testing.T) {
	app := BuildCLIApp()
	set := flag.NewFlagSet("image-list", flag.ContinueOnError)
	set.Bool("with-cves", false, "")
	set.Bool("verbose", false, "")

	if err := set.Parse([]string{"--verbose", "rke2-traefik"}); err != nil {
		t.Fatalf("failed to parse flags: %v", err)
	}

	ctx := cli.NewContext(app, set, nil)
	err := runImageListCommand(ctx)
	if err == nil {
		t.Fatalf("expected validation error, got nil")
	}

	if !strings.Contains(err.Error(), "--verbose requires --with-cves") {
		t.Fatalf("unexpected error: %v", err)
	}

	var exitErr cli.ExitCoder
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected cli exit error, got %T", err)
	}
	if exitErr.ExitCode() != 2 {
		t.Fatalf("unexpected exit code: %d", exitErr.ExitCode())
	}
}

func TestRunImagePatchCommandRejectsExtraArguments(t *testing.T) {
	app := BuildCLIApp()
	set := flag.NewFlagSet("image-patch", flag.ContinueOnError)
	set.Bool("dry-run", false, "")

	if err := set.Parse([]string{"--dry-run", "rke2-traefik", "extra"}); err != nil {
		t.Fatalf("failed to parse flags: %v", err)
	}

	ctx := cli.NewContext(app, set, nil)
	err := runImagePatchCommand(ctx)
	if err == nil {
		t.Fatalf("expected validation error, got nil")
	}

	if !strings.Contains(err.Error(), "unexpected extra argument(s): extra") {
		t.Fatalf("unexpected error: %v", err)
	}

	var exitErr cli.ExitCoder
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected cli exit error, got %T", err)
	}
	if exitErr.ExitCode() != 2 {
		t.Fatalf("unexpected exit code: %d", exitErr.ExitCode())
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

	_, err := resolvePatchTargetTag(repository, "v1.14.1-build20260206")
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

	targetTag, err := resolvePatchTargetTag(repository, "v1.14.1-build20260206")
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

func useInMemoryPatchLimitStateBackend(t *testing.T) {
	t.Helper()

	stored := patchLimitState{Entries: map[string]patchLimitEntry{}}
	originalLoad := loadPatchLimitStateFromBackend
	originalSave := savePatchLimitStateToBackend
	originalEnsureNamespace := ensureStateNamespace

	ensureStateNamespace = func(_ string) error {
		return nil
	}

	loadPatchLimitStateFromBackend = func(_ string) (patchLimitState, string, error) {
		copied := patchLimitState{Entries: map[string]patchLimitEntry{}}
		for key, entry := range stored.Entries {
			copied.Entries[key] = entry
		}
		return copied, "", nil
	}

	savePatchLimitStateToBackend = func(_ string, state patchLimitState, _ string) error {
		copied := patchLimitState{Entries: map[string]patchLimitEntry{}}
		for key, entry := range state.Entries {
			copied.Entries[key] = entry
		}
		stored = copied
		return nil
	}

	t.Cleanup(func() {
		loadPatchLimitStateFromBackend = originalLoad
		savePatchLimitStateToBackend = originalSave
		ensureStateNamespace = originalEnsureNamespace
	})
}

func TestEvaluatePatchLimit_OnlyOneForwardPatchPerComponentAndClusterVersion(t *testing.T) {
	useInMemoryPatchLimitStateBackend(t)

	originalClusterVersionResolver := clusterVersionResolver
	clusterVersionResolver = func() (string, error) {
		return "v1.35.2+rke2r1", nil
	}
	t.Cleanup(func() {
		clusterVersionResolver = originalClusterVersionResolver
	})

	decision, err := evaluatePatchLimit("rke2-traefik", "v3.6.7-build20260301", "v3.6.8-build20260302")
	if err != nil {
		t.Fatalf("unexpected error during first patch evaluation: %v", err)
	}

	if !decision.ShouldPersist {
		t.Fatalf("expected first patch decision to require persistence")
	}

	if err := persistPatchLimitDecision(decision); err != nil {
		t.Fatalf("unexpected persistence error: %v", err)
	}

	_, err = evaluatePatchLimit("rke2-traefik", "v3.6.8-build20260302", "v3.6.9-build20260303")
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

func TestEvaluatePatchLimit_RequiresReconcileAfterRKE2Upgrade(t *testing.T) {
	useInMemoryPatchLimitStateBackend(t)

	clusterVersion := "v1.35.2+rke2r1"
	originalClusterVersionResolver := clusterVersionResolver
	clusterVersionResolver = func() (string, error) {
		return clusterVersion, nil
	}
	t.Cleanup(func() {
		clusterVersionResolver = originalClusterVersionResolver
	})

	firstDecision, err := evaluatePatchLimit("rke2-traefik", "v3.6.7-build20260301", "v3.6.8-build20260302")
	if err != nil {
		t.Fatalf("unexpected first patch evaluation error: %v", err)
	}
	if err := persistPatchLimitDecision(firstDecision); err != nil {
		t.Fatalf("unexpected first persistence error: %v", err)
	}

	clusterVersion = "v1.36.0+rke2r1"
	_, err = evaluatePatchLimit("rke2-traefik", "v3.6.8-build20260302", "v3.6.9-build20260303")
	if err == nil {
		t.Fatalf("expected patch to be blocked until reconcile after cluster version change")
	}

	if !strings.Contains(err.Error(), "reconcile") {
		t.Fatalf("expected reconcile guidance after cluster version change, got %v", err)
	}
}
