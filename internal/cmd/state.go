package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/manuelbuil/rke2-patcher/internal/components"
	"github.com/manuelbuil/rke2-patcher/internal/kube"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
)

const (
	patchLimitStateNamespaceEnv = "RKE2_PATCHER_CVE_NAMESPACE"
	defaultPatchLimitNamespace  = "rke2-patcher"
)

var (
	loadPatchLimitStateFromBackend = loadPatchLimitStateFromKubernetes
	savePatchLimitStateToBackend   = savePatchLimitStateToKubernetes
	ensureStateNamespace           = kube.EnsureNamespace
)

func evaluatePatchLimit(componentName string, currentTag string, targetTag string) (patchLimitDecision, error) {
	clusterVersion, err := clusterVersionResolver()
	if err != nil {
		return patchLimitDecision{}, fmt.Errorf("failed to resolve cluster version for patch-limit check: %w", err)
	}

	namespace := patchLimitStateNamespace()
	state, _, err := loadPatchLimitStateFromBackend(namespace)
	if err != nil {
		return patchLimitDecision{}, err
	}

	for _, entry := range state.Entries {
		if strings.TrimSpace(entry.ClusterVersion) != clusterVersion {
			componentName := components.CLIName(entry.Component)
			return patchLimitDecision{}, fmt.Errorf("refusing to patch: active patch for component %q from RKE2 %s exists; run 'rke2-patcher image-reconcile %s' first", componentName, entry.ClusterVersion, componentName)
		}
	}

	entryKey := patchLimitEntryKey(clusterVersion, componentName)
	if existing, found := state.Entries[entryKey]; found {
		return patchLimitDecision{}, fmt.Errorf("refusing to patch: component %q was already patched once for RKE2 %s (baseline: %q, patched-to: %q); upgrade RKE2 to patch again", componentName, clusterVersion, existing.BaselineTag, existing.PatchedToTag)
	}

	entry := patchLimitEntry{
		Component:      componentName,
		ClusterVersion: clusterVersion,
		BaselineTag:    currentTag,
		PatchedToTag:   targetTag,
	}

	return patchLimitDecision{
		ShouldPersist:  true,
		StateNamespace: namespace,
		EntryKey:       entryKey,
		Entry:          entry,
	}, nil
}

func persistPatchLimitDecision(decision patchLimitDecision) error {
	if !decision.ShouldPersist {
		return nil
	}

	stateNamespace := strings.TrimSpace(decision.StateNamespace)
	if stateNamespace == "" {
		stateNamespace = patchLimitStateNamespace()
	}

	if err := ensureStateNamespace(stateNamespace); err != nil {
		return err
	}

	for attempt := 0; attempt < 5; attempt++ {
		state, resourceVersion, err := loadPatchLimitStateFromBackend(stateNamespace)
		if err != nil {
			return err
		}

		if existing, found := state.Entries[decision.EntryKey]; found {
			if existing.PatchedToTag == decision.Entry.PatchedToTag && existing.BaselineTag == decision.Entry.BaselineTag {
				return nil
			}

			return fmt.Errorf("component %q is already recorded as patched once for RKE2 %s", existing.Component, existing.ClusterVersion)
		}

		state.Entries[decision.EntryKey] = decision.Entry
		err = savePatchLimitStateToBackend(stateNamespace, state, resourceVersion)
		if err == nil {
			return nil
		}

		if k8serrors.IsConflict(err) || k8serrors.IsAlreadyExists(err) {
			continue
		}

		return err
	}

	return fmt.Errorf("failed to persist patch-limit state in ConfigMap %s/%s after retries", stateNamespace, kube.StateConfigMapName)
}

func patchLimitStateNamespace() string {
	namespace := strings.TrimSpace(os.Getenv(patchLimitStateNamespaceEnv))
	if namespace == "" {
		return defaultPatchLimitNamespace
	}

	return namespace
}

func patchLimitEntryKey(clusterVersion string, componentName string) string {
	return strings.TrimSpace(clusterVersion) + "|" + strings.ToLower(strings.TrimSpace(componentName))
}

func loadPatchLimitStateFromKubernetes(namespace string) (patchLimitState, string, error) {
	state := patchLimitState{Entries: map[string]patchLimitEntry{}}

	content, resourceVersion, err := kube.LoadStateConfigMapDataWithResourceVersion(namespace)
	if err != nil {
		return patchLimitState{}, "", err
	}

	if strings.TrimSpace(content) == "" {
		return state, resourceVersion, nil
	}

	if err := json.Unmarshal([]byte(content), &state); err != nil {
		return patchLimitState{}, "", fmt.Errorf("failed to parse patch-limit state payload in ConfigMap %s/%s key %q: %w", namespace, kube.StateConfigMapName, kube.StateConfigMapDataKey, err)
	}

	if state.Entries == nil {
		state.Entries = map[string]patchLimitEntry{}
	}

	return state, resourceVersion, nil
}

func savePatchLimitStateToKubernetes(namespace string, state patchLimitState, resourceVersion string) error {
	if state.Entries == nil {
		state.Entries = map[string]patchLimitEntry{}
	}

	content, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize patch-limit state: %w", err)
	}

	if err := kube.SaveStateConfigMapDataWithResourceVersion(namespace, string(content), resourceVersion); err != nil {
		return err
	}

	return nil
}

func staleEntryKeys(state patchLimitState, currentVersion string) []string {
	var keys []string
	for key, entry := range state.Entries {
		if strings.TrimSpace(entry.ClusterVersion) != currentVersion {
			keys = append(keys, key)
		}
	}
	return keys
}

func removeEntriesFromState(namespace string, keysToRemove []string) error {
	for attempt := 0; attempt < 5; attempt++ {
		state, resourceVersion, err := loadPatchLimitStateFromBackend(namespace)
		if err != nil {
			return err
		}

		for _, key := range keysToRemove {
			delete(state.Entries, key)
		}

		err = savePatchLimitStateToBackend(namespace, state, resourceVersion)
		if err == nil {
			return nil
		}

		if k8serrors.IsConflict(err) || k8serrors.IsAlreadyExists(err) {
			continue
		}

		return err
	}

	return fmt.Errorf("failed to remove stale entries from state in ConfigMap %s/%s after retries", namespace, kube.StateConfigMapName)
}

func ensureManifestsDirectoryExists(filePath string) error {
	manifestsDir := strings.TrimSpace(filepath.Dir(filePath))
	if manifestsDir == "" {
		return fmt.Errorf("failed to resolve manifests directory from output path %q; set RKE2_PATCHER_DATA_DIR (for example /var/lib/rancher/rke2)", filePath)
	}

	info, err := os.Stat(manifestsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("manifests directory %q does not exist; set RKE2_PATCHER_DATA_DIR to point to the RKE2 data directory", manifestsDir)
		}
		return fmt.Errorf("failed to verify manifests directory %q: %w", manifestsDir, err)
	}

	if !info.IsDir() {
		return fmt.Errorf("manifests path %q is not a directory; set RKE2_PATCHER_DATA_DIR to point to the RKE2 data directory", manifestsDir)
	}

	return nil
}
