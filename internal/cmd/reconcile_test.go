package cmd

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/manuelbuil/PoCs/2026/rke2-patcher/internal/components"
	cli "github.com/urfave/cli/v2"
)

func TestEvaluatePatchLimit_BlocksWhenStaleVersionExists(t *testing.T) {
	t.Setenv(patchLimitStateNamespaceEnv, "")

	originalResolver := clusterVersionResolver
	clusterVersionResolver = func() (string, error) {
		return "v1.35.2+rke2r1", nil
	}
	t.Cleanup(func() { clusterVersionResolver = originalResolver })

	originalLoad := loadPatchLimitStateFromBackend
	loadPatchLimitStateFromBackend = func(namespace string) (patchLimitState, string, error) {
		state := patchLimitState{
			Entries: map[string]patchLimitEntry{
				"v1.35.1+rke2r1|rke2-traefik": {
					Component:      "rke2-traefik",
					ClusterVersion: "v1.35.1+rke2r1",
					BaselineTag:    "v3.6.7",
					PatchedToTag:   "v3.6.9",
				},
			},
		}
		return state, "1", nil
	}
	t.Cleanup(func() { loadPatchLimitStateFromBackend = originalLoad })

	_, err := evaluatePatchLimit("traefik", "v3.6.9", "v3.6.10", false)
	if err == nil {
		t.Fatalf("expected error when stale version entry exists, got nil")
	}

	if !strings.Contains(err.Error(), "reconcile") {
		t.Fatalf("expected error to mention reconcile, got: %v", err)
	}

	if !strings.Contains(err.Error(), "reconcile rke2-traefik") {
		t.Fatalf("expected error to suggest component-scoped reconcile, got: %v", err)
	}

	if !strings.Contains(err.Error(), "v1.35.1+rke2r1") {
		t.Fatalf("expected error to mention stale version, got: %v", err)
	}
}

func TestEvaluatePatchLimit_AllowsWhenAllEntriesMatchCurrentVersion(t *testing.T) {
	t.Setenv(patchLimitStateNamespaceEnv, "")

	originalResolver := clusterVersionResolver
	clusterVersionResolver = func() (string, error) {
		return "v1.35.2+rke2r1", nil
	}
	t.Cleanup(func() { clusterVersionResolver = originalResolver })

	originalLoad := loadPatchLimitStateFromBackend
	loadPatchLimitStateFromBackend = func(namespace string) (patchLimitState, string, error) {
		state := patchLimitState{
			Entries: map[string]patchLimitEntry{
				"v1.35.2+rke2r1|flannel": {
					Component:      "flannel",
					ClusterVersion: "v1.35.2+rke2r1",
					BaselineTag:    "v0.26.0",
					PatchedToTag:   "v0.26.1",
				},
			},
		}
		return state, "1", nil
	}
	t.Cleanup(func() { loadPatchLimitStateFromBackend = originalLoad })

	decision, err := evaluatePatchLimit("traefik", "v3.6.9", "v3.6.10", false)
	if err != nil {
		t.Fatalf("expected patch to be allowed when no stale-version entries exist, got: %v", err)
	}

	if !decision.ShouldPersist {
		t.Fatalf("expected decision to require persistence")
	}
}

func TestStaleEntryKeys_ReturnsOnlyDifferentVersionKeys(t *testing.T) {
	state := patchLimitState{
		Entries: map[string]patchLimitEntry{
			"v1.35.1+rke2r1|traefik": {ClusterVersion: "v1.35.1+rke2r1"},
			"v1.35.2+rke2r1|flannel": {ClusterVersion: "v1.35.2+rke2r1"},
			"v1.35.1+rke2r1|calico":  {ClusterVersion: "v1.35.1+rke2r1"},
		},
	}

	keys := staleEntryKeys(state, "v1.35.2+rke2r1")

	if len(keys) != 2 {
		t.Fatalf("expected 2 stale keys, got %d: %v", len(keys), keys)
	}

	for _, k := range keys {
		if strings.Contains(k, "v1.35.2+rke2r1") {
			t.Fatalf("expected only v1.35.1 entries to be stale, got: %s", k)
		}
	}
}

func TestReconcileEntry_StripsGeneratedValuesFromFile(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "traefik-config-rke2-patcher.yaml")

	fileContent := `apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: rke2-traefik
  namespace: kube-system
spec:
  valuesContent: |-
    image:
      repository: rancher/hardened-traefik
      tag: v3.4.0
    service:
      type: ClusterIP
`
	if err := os.WriteFile(filePath, []byte(fileContent), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	entry := patchLimitEntry{
		Component:              "traefik",
		ClusterVersion:         "v1.35.1+rke2r1",
		BaselineTag:            "v3.3.0",
		PatchedToTag:           "v3.4.0",
		FilePath:               filePath,
		GeneratedValuesContent: "image:\n  repository: rancher/hardened-traefik\n  tag: v3.4.0",
	}

	if err := reconcileEntry(entry); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	updated, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read updated file: %v", err)
	}

	updatedStr := string(updated)
	if strings.Contains(updatedStr, "repository:") || strings.Contains(updatedStr, "tag:") {
		t.Fatalf("expected patcher image keys to be removed, got:\n%s", updatedStr)
	}

	if !strings.Contains(updatedStr, "type: ClusterIP") {
		t.Fatalf("expected user service values to be preserved, got:\n%s", updatedStr)
	}
}

func TestReconcileEntry_NoOpForLegacyEntryWithoutFilePath(t *testing.T) {
	entry := patchLimitEntry{
		Component:      "traefik",
		ClusterVersion: "v1.35.1+rke2r1",
		FilePath:       "",
	}

	if err := reconcileEntry(entry); err != nil {
		t.Fatalf("unexpected error for legacy entry: %v", err)
	}
}

func TestReconcileEntry_NoOpWhenFileDoesNotExist(t *testing.T) {
	entry := patchLimitEntry{
		Component:              "traefik",
		ClusterVersion:         "v1.35.1+rke2r1",
		FilePath:               "/nonexistent/path/traefik-config-rke2-patcher.yaml",
		GeneratedValuesContent: "image:\n  repository: rancher/hardened-traefik\n  tag: v3.4.0",
	}

	if err := reconcileEntry(entry); err != nil {
		t.Fatalf("unexpected error when file does not exist: %v", err)
	}
}

func TestRunReconcile_OnlyTouchesTargetComponent(t *testing.T) {
	useInMemoryPatchLimitStateBackend(t)

	originalResolver := clusterVersionResolver
	clusterVersionResolver = func() (string, error) {
		return "v1.35.2+rke2r1", nil
	}
	t.Cleanup(func() {
		clusterVersionResolver = originalResolver
	})

	tempDir := t.TempDir()
	traefikFilePath := filepath.Join(tempDir, "traefik-config-rke2-patcher.yaml")
	flannelFilePath := filepath.Join(tempDir, "flannel-config-rke2-patcher.yaml")

	traefikContent := `apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: rke2-traefik
  namespace: kube-system
spec:
  valuesContent: |-
    image:
      repository: rancher/hardened-traefik
      tag: v3.4.0
    service:
      type: ClusterIP
`
	flannelContent := `apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
	name: rke2-flannel
  namespace: kube-system
spec:
  valuesContent: |-
		image:
			repository: rancher/hardened-flannel
        tag: v1.0.0
    feature:
      enabled: true
`

	if err := os.WriteFile(traefikFilePath, []byte(traefikContent), 0644); err != nil {
		t.Fatalf("failed to write traefik file: %v", err)
	}
	if err := os.WriteFile(flannelFilePath, []byte(flannelContent), 0644); err != nil {
		t.Fatalf("failed to write flannel file: %v", err)
	}

	traefikComponent, err := components.Resolve("traefik")
	if err != nil {
		t.Fatalf("failed to resolve traefik component: %v", err)
	}

	flannelComponent, err := components.Resolve("flannel")
	if err != nil {
		t.Fatalf("failed to resolve flannel component: %v", err)
	}

	if err := persistPatchLimitDecision(patchLimitDecision{
		ShouldPersist:  true,
		StateNamespace: patchLimitStateNamespace(),
		EntryKey:       patchLimitEntryKey("v1.35.1+rke2r1", traefikComponent.Name),
		Entry: patchLimitEntry{
			Component:              traefikComponent.Name,
			ClusterVersion:         "v1.35.1+rke2r1",
			BaselineTag:            "v3.3.0",
			PatchedToTag:           "v3.4.0",
			FilePath:               traefikFilePath,
			GeneratedValuesContent: "image:\n  repository: rancher/hardened-traefik\n  tag: v3.4.0",
		},
	}); err != nil {
		t.Fatalf("failed to persist traefik state: %v", err)
	}

	if err := persistPatchLimitDecision(patchLimitDecision{
		ShouldPersist:  true,
		StateNamespace: patchLimitStateNamespace(),
		EntryKey:       patchLimitEntryKey("v1.35.1+rke2r1", flannelComponent.Name),
		Entry: patchLimitEntry{
			Component:              flannelComponent.Name,
			ClusterVersion:         "v1.35.1+rke2r1",
			BaselineTag:            "v0.9.0",
			PatchedToTag:           "v1.0.0",
			FilePath:               flannelFilePath,
			GeneratedValuesContent: "image:\n  repository: rancher/hardened-flannel\n  tag: v1.0.0",
		},
	}); err != nil {
		t.Fatalf("failed to persist flannel state: %v", err)
	}

	if err := runReconcile(traefikComponent); err != nil {
		t.Fatalf("unexpected reconcile error: %v", err)
	}

	updatedTraefik, err := os.ReadFile(traefikFilePath)
	if err != nil {
		t.Fatalf("failed to read traefik file: %v", err)
	}
	if strings.Contains(string(updatedTraefik), "repository: rancher/hardened-traefik") || strings.Contains(string(updatedTraefik), "tag: v3.4.0") {
		t.Fatalf("expected traefik patcher keys to be removed, got:\n%s", string(updatedTraefik))
	}

	updatedFlannel, err := os.ReadFile(flannelFilePath)
	if err != nil {
		t.Fatalf("failed to read flannel file: %v", err)
	}
	if !strings.Contains(string(updatedFlannel), "repository: rancher/hardened-flannel") || !strings.Contains(string(updatedFlannel), "tag: v1.0.0") {
		t.Fatalf("expected flannel file to remain untouched, got:\n%s", string(updatedFlannel))
	}

	state, _, err := loadPatchLimitStateFromBackend(patchLimitStateNamespace())
	if err != nil {
		t.Fatalf("failed to load state: %v", err)
	}
	if _, found := state.Entries[patchLimitEntryKey("v1.35.1+rke2r1", traefikComponent.Name)]; found {
		t.Fatalf("expected traefik stale state entry to be removed")
	}
	if _, found := state.Entries[patchLimitEntryKey("v1.35.1+rke2r1", flannelComponent.Name)]; !found {
		t.Fatalf("expected flannel stale state entry to remain")
	}
}

func TestRunReconcileCommand_RequiresComponent(t *testing.T) {
	app := BuildCLIApp()
	set := flag.NewFlagSet("reconcile", flag.ContinueOnError)

	if err := set.Parse([]string{}); err != nil {
		t.Fatalf("failed to parse flags: %v", err)
	}

	ctx := cli.NewContext(app, set, nil)
	err := runReconcileCommand(ctx)
	if err == nil {
		t.Fatalf("expected validation error, got nil")
	}

	if !strings.Contains(err.Error(), "component is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}
