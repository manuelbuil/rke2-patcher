package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/manuelbuil/PoCs/2026/rke2-patcher/internal/components"
	"github.com/manuelbuil/PoCs/2026/rke2-patcher/internal/cve"
	"github.com/manuelbuil/PoCs/2026/rke2-patcher/internal/kube"
	"github.com/manuelbuil/PoCs/2026/rke2-patcher/internal/patcher"
	"github.com/manuelbuil/PoCs/2026/rke2-patcher/internal/registry"
)

// runCVE lists the CVEs for the currently running image of a component
func runCVE(component components.Component) error {
	runningImages, err := kube.ListRunningImages(component.Workload, component.Repository)
	if err != nil {
		return fmt.Errorf("running image unavailable: %w", err)
	}

	image := runningImages[0].Image
	resultCVEs, err := cve.ListCVEsForImage(image)
	if err != nil {
		return fmt.Errorf("failed to scan image %q: %w", image, err)
	}

	fmt.Printf("component: %s\n", component.Name)
	fmt.Printf("image: %s\n", image)
	fmt.Printf("scanner: %s\n", resultCVEs.Tool)

	if len(resultCVEs.CVEs) == 0 {
		fmt.Println("CVEs: none")
		return nil
	}

	fmt.Printf("CVEs (%d):\n", len(resultCVEs.CVEs))
	for _, id := range resultCVEs.CVEs {
		fmt.Printf("- %s\n", id)
	}

	return nil
}

// runImageList lists the available tags for the component
func runImageList(component components.Component, options imageListOptions) error {
	runningImages, err := kube.ListRunningImages(component.Workload, component.Repository)
	if err != nil {
		return fmt.Errorf("running image unavailable: %w", err)
	}

	// runningImages is ordered by descending pod count, so the first image is the most widely used one
	currentImage := runningImages[0].Image
	currentImageName, currentTag := kube.SplitImage(currentImage)
	if currentTag == "" {
		return fmt.Errorf("running image %q does not include a tag", currentImage)
	}

	tagsForSelection, err := registry.ListTags(component.Repository, 200)
	if err != nil {
		if options.WithCVEs {
			return fmt.Errorf("failed to list tags for CVE selection: %w", err)
		}
		return err
	}

	tagsToShow, previousTag := selectTagsForCVEListing(tagsForSelection, currentTag)
	if len(tagsToShow) == 0 {
		if options.WithCVEs {
			return fmt.Errorf("failed to determine tags to scan for current tag %q", currentTag)
		}
		return fmt.Errorf("failed to determine tags to show for current tag %q", currentTag)
	}

	if options.WithCVEs {
		return runImageListWithCVEs(component, currentImageName, currentTag, tagsToShow, previousTag, options.Verbose)
	}

	tagInfoByName := make(map[string]registry.Tag, len(tagsForSelection))
	for _, tag := range tagsForSelection {
		tagInfoByName[tag.Name] = tag
	}

	inUseTags := make(map[string]struct{})
	for _, summary := range runningImages {
		_, tag := kube.SplitImage(summary.Image)
		if tag != "" {
			inUseTags[tag] = struct{}{}
		}
	}

	fmt.Printf("component: %s\n", component.Name)
	fmt.Printf("repository: %s\n", component.Repository)
	fmt.Printf("running image(s):\n")
	for _, summary := range runningImages {
		fmt.Printf("- %s (pods: %d)\n", summary.Image, summary.Count)
	}

	fmt.Printf("available tags (%d):\n", len(tagsToShow))
	for _, tagName := range tagsToShow {
		tag, found := tagInfoByName[tagName]
		if !found {
			continue
		}

		suffix := ""
		if _, found := inUseTags[tag.Name]; found {
			suffix = " <-- in use"
		}

		if !tag.LastUpdated.IsZero() {
			fmt.Printf("- %s (updated %s)%s\n", tag.Name, tag.LastUpdated.Format("2006-01-02T15:04:05Z07:00"), suffix)
			continue
		}

		fmt.Printf("- %s%s\n", tag.Name, suffix)
	}

	return nil
}

func runImageListWithCVEs(component components.Component, imageName, currentTag string, tagsToScan []string, previousTag string, verbose bool) error {
	targetImages := make([]string, 0, len(tagsToScan))
	for _, tagName := range tagsToScan {
		targetImages = append(targetImages, fmt.Sprintf("%s:%s", imageName, tagName))
	}

	resultsByImage, errorsByImage, scanErr := cve.ListCVEsForImages(targetImages)
	if scanErr != nil {
		return scanErr
	}

	cveByTag := make(map[string]cveListEntry, len(tagsToScan))
	for _, tagName := range tagsToScan {
		targetImage := fmt.Sprintf("%s:%s", imageName, tagName)
		if imageErr, found := errorsByImage[targetImage]; found {
			cveByTag[tagName] = cveListEntry{Error: fmt.Sprintf("%v", imageErr)}
			continue
		}

		result, found := resultsByImage[targetImage]
		if !found {
			cveByTag[tagName] = cveListEntry{Error: "missing result"}
			continue
		}

		cveByTag[tagName] = cveListEntry{CVEs: result.CVEs}
	}

	printImageListWithCVEs(component, tagsToScan, currentTag, previousTag, cveByTag, verbose)
	return nil
}

func runImagePatch(component components.Component, options imagePatchOptions) error {
	runningImages, err := kube.ListRunningImages(component.Workload, component.Repository)
	if err != nil {
		return fmt.Errorf("running image unavailable: %w", err)
	}

	runningImage := runningImages[0].Image
	currentImageName, currentImageTag := kube.SplitImage(runningImage)

	targetTagName, err := resolvePatchTargetTag(component.Repository, currentImageTag, options.Revert)
	if err != nil {
		return err
	}

	patchDecision, err := evaluatePatchLimit(component.Name, currentImageTag, targetTagName, options.Revert)
	if err != nil {
		return err
	}

	filePath, generatedContent := patcher.BuildHelmChartConfigWithDataDir(component.Name, component.HelmChartConfigName, currentImageName, targetTagName, "")
	if options.DryRun {
		printPatchPreview(component.Name, runningImage, currentImageTag, targetTagName, filePath, generatedContent)
		return nil
	}

	generatedValuesContent, err := patcher.ExtractValuesContent(generatedContent)
	if err != nil {
		return fmt.Errorf("failed to extract generated valuesContent: %w", err)
	}
	patchDecision.Entry.FilePath = filePath
	patchDecision.Entry.GeneratedValuesContent = generatedValuesContent

	targetName, targetNamespace, err := patcher.HelmChartConfigIdentityFromContent(generatedContent)
	if err != nil {
		return err
	}

	contentToWrite := generatedContent
	conflicts, err := kube.ListHelmChartConfigsByIdentity(targetName, targetNamespace)
	if err != nil {
		return err
	}

	if len(conflicts) > 0 {
		fmt.Printf("warning: found a HelmChartConfig object in the cluster for this component:\n")
		for _, conflict := range conflicts {
			fmt.Printf("- %s/%s\n", conflict.Namespace, conflict.Name)
		}

		firstConfirm, err := promptYesNo("Merging generated and existing HelmChartConfig values will be tried. Continue? [Yes/No]: ")
		if err != nil {
			return err
		}
		if !firstConfirm {
			fmt.Println("aborted: merge was not approved")
			return nil
		}

		existingContents := make([]string, 0, len(conflicts))
		for _, conflict := range conflicts {
			existingContents = append(existingContents, conflict.Content)
		}

		mergedContent, err := patcher.MergeHelmChartConfigWithContents(generatedContent, existingContents)
		if err != nil {
			return err
		}
		contentToWrite = mergedContent

		printPatchPreview(component.Name, runningImage, currentImageTag, targetTagName, filePath, contentToWrite)
		secondConfirm, err := promptYesNo("Apply this HelmChartConfig now? [Yes/No]: ")
		if err != nil {
			return err
		}
		if !secondConfirm {
			fmt.Println("aborted: write was not approved")
			return nil
		}
	}

	if err := ensureManifestsDirectoryExists(filePath); err != nil {
		return err
	}

	writeTime := time.Now()
	if err := patcher.WriteHelmChartConfigContent(filePath, contentToWrite); err != nil {
		return err
	}

	// Verify the file was actually written: it must exist and its modification
	// time must be >= the moment we called Write, ruling out a stale pre-existing
	// file that was untouched due to a silent failure.
	if err := verifyFileWritten(filePath, writeTime); err != nil {
		return fmt.Errorf("file verification failed after write: %w", err)
	}

	// Persist patch-limit state only after the file is confirmed on disk.
	if err := persistPatchLimitDecision(patchDecision); err != nil {
		return fmt.Errorf("failed to persist patch-limit state: %w", err)
	}

	printPatchApplied(component.Name, runningImage, currentImageTag, targetTagName, filePath)
	return nil
}

func runReconcile(component components.Component) error {
	currentVersion, err := clusterVersionResolver()
	if err != nil {
		return fmt.Errorf("failed to resolve cluster version: %w", err)
	}

	namespace := patchLimitStateNamespace()
	state, _, err := loadPatchLimitStateFromBackend(namespace)
	if err != nil {
		return err
	}

	staleKeys := make([]string, 0)
	for key, entry := range state.Entries {
		if strings.TrimSpace(entry.ClusterVersion) == currentVersion {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(entry.Component), strings.TrimSpace(component.Name)) {
			continue
		}
		staleKeys = append(staleKeys, key)
	}

	if len(staleKeys) == 0 {
		printReconcileAlreadyCurrent(components.CLIName(component.Name))
		return nil
	}

	for _, key := range staleKeys {
		entry := state.Entries[key]
		if err := reconcileEntry(entry); err != nil {
			return fmt.Errorf("failed to reconcile component %q: %w", entry.Component, err)
		}
		printReconcileApplied(entry)
	}

	return removeEntriesFromState(namespace, staleKeys)
}

// verifyFileWritten checks that filePath exists and was last modified no earlier
// than writeTime, confirming a recent successful write rather than a stale file.
func verifyFileWritten(filePath string, writeTime time.Time) error {
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("file %q not found after write: %w", filePath, err)
	}
	// Truncate to second precision: most filesystems store mtime at 1-second
	// granularity, so comparing with a nanosecond-precise writeTime would
	// spuriously fail when both timestamps fall within the same second.
	if info.ModTime().Before(writeTime.Truncate(time.Second)) {
		return fmt.Errorf("file %q exists but was not updated (mtime %s predates write at %s)",
			filePath, info.ModTime().Format(time.RFC3339), writeTime.Format(time.RFC3339))
	}
	return nil
}

func reconcileEntry(entry patchLimitEntry) error {
	filePath := strings.TrimSpace(entry.FilePath)
	if filePath == "" {
		return nil
	}

	generatedValuesContent := strings.TrimSpace(entry.GeneratedValuesContent)
	if generatedValuesContent == "" {
		return nil
	}

	existingContent, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read HelmChartConfig file %q: %w", filePath, err)
	}

	updatedContent, err := patcher.SubtractPatcherValuesContent(string(existingContent), generatedValuesContent)
	if err != nil {
		return fmt.Errorf("failed to strip patcher values from %q: %w", filePath, err)
	}

	if err := patcher.WriteHelmChartConfigContent(filePath, updatedContent); err != nil {
		return fmt.Errorf("failed to write updated HelmChartConfig to %q: %w", filePath, err)
	}

	return nil
}
