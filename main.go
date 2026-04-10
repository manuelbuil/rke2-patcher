package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/manuelbuil/PoCs/2026/rke2-patcher/internal/components"
	"github.com/manuelbuil/PoCs/2026/rke2-patcher/internal/cve"
	"github.com/manuelbuil/PoCs/2026/rke2-patcher/internal/kube"
	"github.com/manuelbuil/PoCs/2026/rke2-patcher/internal/patcher"
	"github.com/manuelbuil/PoCs/2026/rke2-patcher/internal/registry"
)

const (
	version                = "0.6.4"
	defaultRKE2DataDir     = "/var/lib/rancher/rke2"
	patchLimitCacheDirEnv  = "RKE2_PATCHER_CACHE_DIR"
	patchLimitStateSubPath = "server/rke2-patcher-cache/patch-limit-state.json"
)

var clusterVersionResolver = kube.ClusterVersion

type imageListOptions struct {
	WithCVEs bool
	Verbose  bool
}

type cveListEntry struct {
	CVEs  []string
	Error string
}

type imagePatchOptions struct {
	DryRun bool
	Revert bool
}

type patchLimitState struct {
	Entries map[string]patchLimitEntry `json:"entries"`
}

type patchLimitEntry struct {
	Component      string `json:"component"`
	ClusterVersion string `json:"clusterVersion"`
	BaselineTag    string `json:"baselineTag"`
	PatchedToTag   string `json:"patchedToTag"`
}

type patchLimitDecision struct {
	ShouldPersist bool
	StateFilePath string
	EntryKey      string
	Entry         patchLimitEntry
}

func main() {
	log.SetFlags(0)

	if len(os.Args) == 2 && strings.TrimSpace(os.Args[1]) == "--version" {
		printVersion()
		return
	}

	if len(os.Args) < 3 {
		printUsage()
		os.Exit(2)
	}

	command := strings.TrimSpace(os.Args[1])
	componentName := strings.TrimSpace(os.Args[2])
	extraArgs := os.Args[3:]

	component, err := components.Resolve(componentName)
	if err != nil {
		log.Printf("%v", err)
		printUsage()
		os.Exit(2)
	}

	switch command {
	case "image-cve":
		if len(extraArgs) > 0 {
			log.Printf("unsupported image-cve option(s): %s", strings.Join(extraArgs, " "))
			printUsage()
			os.Exit(2)
		}
		if err := runCVE(component); err != nil {
			log.Fatal(err)
		}
	case "image-list":
		options, parseErr := parseImageListOptions(extraArgs)
		if parseErr != nil {
			log.Printf("%v", parseErr)
			printUsage()
			os.Exit(2)
		}
		if err := runImageList(component, options); err != nil {
			log.Fatal(err)
		}
	case "image-patch":
		options, parseErr := parseImagePatchOptions(extraArgs)
		if parseErr != nil {
			log.Printf("%v", parseErr)
			printUsage()
			os.Exit(2)
		}

		if err := runImagePatch(component, options); err != nil {
			log.Fatal(err)
		}
	default:
		log.Printf("unsupported command %q", command)
		printUsage()
		os.Exit(2)
	}
}

func parseImagePatchOptions(args []string) (imagePatchOptions, error) {
	options := imagePatchOptions{}

	if len(args) == 0 {
		return options, nil
	}

	for i := 0; i < len(args); i++ {
		arg := strings.TrimSpace(args[i])
		switch {
		case arg == "--dry-run":
			if options.DryRun {
				return imagePatchOptions{}, fmt.Errorf("duplicate --dry-run option")
			}
			options.DryRun = true
		case arg == "--revert":
			if options.Revert {
				return imagePatchOptions{}, fmt.Errorf("duplicate --revert option")
			}
			options.Revert = true
		default:
			return imagePatchOptions{}, fmt.Errorf("unsupported image-patch option(s): %s", strings.Join(args, " "))
		}
	}

	return options, nil
}

func parseImageListOptions(args []string) (imageListOptions, error) {
	options := imageListOptions{}

	if len(args) == 0 {
		return options, nil
	}

	for _, raw := range args {
		arg := strings.TrimSpace(raw)
		switch arg {
		case "--with-cves":
			if options.WithCVEs {
				return imageListOptions{}, fmt.Errorf("duplicate --with-cves option")
			}
			options.WithCVEs = true
		case "--verbose":
			if options.Verbose {
				return imageListOptions{}, fmt.Errorf("duplicate --verbose option")
			}
			options.Verbose = true
		default:
			return imageListOptions{}, fmt.Errorf("unsupported image-list option(s): %s", strings.Join(args, " "))
		}
	}

	if options.Verbose && !options.WithCVEs {
		return imageListOptions{}, fmt.Errorf("--verbose requires --with-cves")
	}

	return options, nil
}

// runCVE lists CVEs for the image of the component
func runCVE(component components.Component) error {
	runningImages, err := kube.ListRunningImages(component.Workload, component.Repository)
	if err != nil {
		return fmt.Errorf("running image unavailable: %w", err)
	}

	image := runningImages[0].Image
	effectiveScannerMode, err := cve.ResolveScanMode()
	if err != nil {
		return err
	}
	log.Printf("scanner mode: %s", effectiveScannerMode)

	result, err := cve.ListForImage(image)
	if err != nil {
		return fmt.Errorf("failed to scan image %q: %w", image, err)
	}

	fmt.Printf("component: %s\n", component.Name)
	fmt.Printf("image: %s\n", image)
	fmt.Printf("scanner mode: %s\n", effectiveScannerMode)
	fmt.Printf("scanner: %s\n", result.Tool)

	if len(result.CVEs) == 0 {
		fmt.Println("CVEs: none")
		return nil
	}

	fmt.Printf("CVEs (%d):\n", len(result.CVEs))
	for _, id := range result.CVEs {
		fmt.Printf("- %s\n", id)
	}

	return nil
}

func runImageList(component components.Component, options imageListOptions) error {
	runningImages, err := kube.ListRunningImages(component.Workload, component.Repository)
	if err != nil {
		return fmt.Errorf("running image unavailable: %w", err)
	}

	if options.WithCVEs {
		currentImage := runningImages[0].Image
		currentImageName, currentTag := kube.SplitImage(currentImage)
		if currentTag == "" {
			return fmt.Errorf("running image %q does not include a tag", currentImage)
		}

		tagsForSelection, err := registry.ListTags(component.Repository, 200)
		if err != nil {
			return fmt.Errorf("failed to list tags for CVE selection: %w", err)
		}

		tagsToScan, previousTag := selectTagsForCVEListing(tagsForSelection, currentTag)
		if len(tagsToScan) == 0 {
			return fmt.Errorf("failed to determine tags to scan for current tag %q", currentTag)
		}

		targetImages := make([]string, 0, len(tagsToScan))
		for _, tagName := range tagsToScan {
			targetImages = append(targetImages, fmt.Sprintf("%s:%s", currentImageName, tagName))
		}

		resultsByImage, errorsByImage, scanErr := cve.ListForImages(targetImages)
		if scanErr != nil {
			return scanErr
		}

		cveByTag := make(map[string]cveListEntry)

		for _, tagName := range tagsToScan {
			targetImage := fmt.Sprintf("%s:%s", currentImageName, tagName)
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

		printImageListWithCVEs(component, tagsToScan, currentTag, previousTag, cveByTag, options.Verbose)
		return nil
	}

	currentImage := runningImages[0].Image
	_, currentTag := kube.SplitImage(currentImage)
	if currentTag == "" {
		return fmt.Errorf("running image %q does not include a tag", currentImage)
	}

	tagsForSelection, err := registry.ListTags(component.Repository, 200)
	if err != nil {
		return err
	}

	tagsToShow, _ := selectTagsForCVEListing(tagsForSelection, currentTag)
	if len(tagsToShow) == 0 {
		return fmt.Errorf("failed to determine tags to show for current tag %q", currentTag)
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
		fmt.Printf("component: %s\n", component.Name)
		fmt.Printf("current image: %s\n", runningImage)
		fmt.Printf("current tag: %s\n", currentImageTag)
		fmt.Printf("new tag: %s\n", targetTagName)
		fmt.Printf("dry-run: true\n")
		fmt.Printf("would write HelmChartConfig: %s\n", filePath)
		fmt.Println("---")
		fmt.Print(generatedContent)

		return nil
	}

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

		fmt.Printf("component: %s\n", component.Name)
		fmt.Printf("current image: %s\n", runningImage)
		fmt.Printf("current tag: %s\n", currentImageTag)
		fmt.Printf("new tag: %s\n", targetTagName)
		fmt.Printf("dry-run: true\n")
		fmt.Printf("would write HelmChartConfig: %s\n", filePath)
		fmt.Println("---")
		fmt.Print(contentToWrite)

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

	err = patcher.WriteHelmChartConfigContent(filePath, contentToWrite)
	if err != nil {
		return err
	}

	if err := persistPatchLimitDecision(patchDecision); err != nil {
		return fmt.Errorf("wrote HelmChartConfig, but failed to persist patch-limit state: %w", err)
	}

	fmt.Printf("component: %s\n", component.Name)
	fmt.Printf("current image: %s\n", runningImage)
	fmt.Printf("current tag: %s\n", currentImageTag)
	fmt.Printf("new tag: %s\n", targetTagName)
	fmt.Printf("wrote HelmChartConfig: %s\n", filePath)

	return nil
}

func evaluatePatchLimit(componentName string, currentTag string, targetTag string, revert bool) (patchLimitDecision, error) {
	clusterVersion, err := clusterVersionResolver()
	if err != nil {
		return patchLimitDecision{}, fmt.Errorf("failed to resolve cluster version for patch-limit/revert check: %w", err)
	}

	stateFilePath := patchLimitStateFilePath()
	state, err := loadPatchLimitState(stateFilePath)
	if err != nil {
		return patchLimitDecision{}, err
	}

	entryKey := patchLimitEntryKey(clusterVersion, componentName)
	if revert {
		existing, found := state.Entries[entryKey]
		if !found {
			return patchLimitDecision{}, fmt.Errorf("refusing to revert: component %q has no recorded baseline for RKE2 %s; reverting below the release baseline is not supported", componentName, clusterVersion)
		}

		baselineTag := strings.TrimSpace(existing.BaselineTag)
		if baselineTag == "" {
			return patchLimitDecision{}, fmt.Errorf("refusing to revert: baseline tag is missing for component %q on RKE2 %s", componentName, clusterVersion)
		}

		targetOlderThanBaseline, compareErr := isTagOlderThan(targetTag, baselineTag)
		if compareErr != nil {
			return patchLimitDecision{}, fmt.Errorf("refusing to revert: failed to compare target tag %q with baseline %q: %w", targetTag, baselineTag, compareErr)
		}

		if targetOlderThanBaseline {
			return patchLimitDecision{}, fmt.Errorf("refusing to revert: target tag %q is older than the release baseline %q for component %q on RKE2 %s", targetTag, baselineTag, componentName, clusterVersion)
		}

		return patchLimitDecision{}, nil
	}

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
		ShouldPersist: true,
		StateFilePath: stateFilePath,
		EntryKey:      entryKey,
		Entry:         entry,
	}, nil
}

func persistPatchLimitDecision(decision patchLimitDecision) error {
	if !decision.ShouldPersist {
		return nil
	}

	state, err := loadPatchLimitState(decision.StateFilePath)
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

	if err := savePatchLimitState(decision.StateFilePath, state); err != nil {
		return err
	}

	return nil
}

func patchLimitStateFilePath() string {
	cacheDir := strings.TrimSpace(os.Getenv(patchLimitCacheDirEnv))
	if cacheDir != "" {
		return filepath.Join(cacheDir, "patch-limit-state.json")
	}

	dataDir := strings.TrimSpace(os.Getenv("RKE2_PATCHER_DATA_DIR"))
	if dataDir == "" {
		dataDir = defaultRKE2DataDir
	}

	return filepath.Join(dataDir, patchLimitStateSubPath)
}

func patchLimitEntryKey(clusterVersion string, componentName string) string {
	return strings.TrimSpace(clusterVersion) + "|" + strings.ToLower(strings.TrimSpace(componentName))
}

func loadPatchLimitState(filePath string) (patchLimitState, error) {
	state := patchLimitState{Entries: map[string]patchLimitEntry{}}

	content, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return state, nil
		}

		return patchLimitState{}, fmt.Errorf("failed to read patch-limit state file %q: %w", filePath, err)
	}

	if strings.TrimSpace(string(content)) == "" {
		return state, nil
	}

	if err := json.Unmarshal(content, &state); err != nil {
		return patchLimitState{}, fmt.Errorf("failed to parse patch-limit state file %q: %w", filePath, err)
	}

	if state.Entries == nil {
		state.Entries = map[string]patchLimitEntry{}
	}

	return state, nil
}

func savePatchLimitState(filePath string, state patchLimitState) error {
	if state.Entries == nil {
		state.Entries = map[string]patchLimitEntry{}
	}

	content, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize patch-limit state: %w", err)
	}

	stateDir := filepath.Dir(filePath)
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		return fmt.Errorf("failed to create patch-limit state directory %q: %w", stateDir, err)
	}

	tmpPath := filePath + ".tmp"
	if err := os.WriteFile(tmpPath, content, 0644); err != nil {
		return fmt.Errorf("failed to write temporary patch-limit state file %q: %w", tmpPath, err)
	}

	if err := os.Rename(tmpPath, filePath); err != nil {
		return fmt.Errorf("failed to replace patch-limit state file %q: %w", filePath, err)
	}

	return nil
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

func promptYesNo(prompt string) (bool, error) {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print(prompt)
		input, err := reader.ReadString('\n')
		if err != nil {
			return false, fmt.Errorf("failed to read user input: %w", err)
		}

		normalized := strings.ToLower(strings.TrimSpace(input))
		switch normalized {
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		default:
			fmt.Println("please answer Yes or No")
		}
	}
}

func resolvePatchTargetTag(repository string, currentTag string, revert bool) (string, error) {
	tags, err := registry.ListTags(repository, 200)
	if err != nil {
		return "", fmt.Errorf("failed to list tags: %w", err)
	}
	orderedTags := orderedComparableTags(tags)
	if len(orderedTags) == 0 {
		return "", fmt.Errorf("failed to determine ordered patchable tags")
	}

	currentIndex := -1
	for index, tagName := range orderedTags {
		if tagName == currentTag && currentIndex == -1 {
			currentIndex = index
		}
	}

	if currentIndex == -1 {
		return "", fmt.Errorf("refusing to patch: current tag %q not found in latest observed tags", currentTag)
	}

	if revert {
		targetIndex := currentIndex + 1
		if targetIndex >= len(orderedTags) {
			return "", fmt.Errorf("refusing to revert: current tag %q is already the oldest available in the observed tag list", currentTag)
		}
		return orderedTags[targetIndex], nil
	}

	targetIndex := currentIndex - 1
	if targetIndex < 0 {
		return "", fmt.Errorf("refusing to patch: current tag %q is already the latest", currentTag)
	}

	targetTag := orderedTags[targetIndex]

	currentComparable, currentParseOK := parseComparableTag(currentTag)
	if !currentParseOK {
		return "", fmt.Errorf("refusing to patch: current tag %q cannot be compared for minor compatibility", currentTag)
	}

	targetComparable, targetParseOK := parseComparableTag(targetTag)
	if !targetParseOK {
		return "", fmt.Errorf("refusing to patch: target tag %q cannot be compared for minor compatibility", targetTag)
	}

	if isNewerMinorRelease(currentComparable, targetComparable) {
		return "", fmt.Errorf("refusing to patch: moving to a newer minor release is not supported (current: %q, target: %q)", currentTag, targetTag)
	}

	return targetTag, nil
}

func isNewerMinorRelease(current comparableTag, target comparableTag) bool {
	if target.Major != current.Major {
		return target.Major > current.Major
	}

	return target.Minor > current.Minor
}

func isTagOlderThan(tagName string, baselineTag string) (bool, error) {
	tagComparable, tagParseOK := parseComparableTag(tagName)
	if !tagParseOK {
		return false, fmt.Errorf("tag %q cannot be compared", tagName)
	}

	baselineComparable, baselineParseOK := parseComparableTag(baselineTag)
	if !baselineParseOK {
		return false, fmt.Errorf("baseline tag %q cannot be compared", baselineTag)
	}

	return compareComparableTags(tagComparable, baselineComparable) < 0, nil
}

func compareComparableTags(left comparableTag, right comparableTag) int {
	if left.Build != right.Build {
		if left.Build > right.Build {
			return 1
		}

		return -1
	}

	if left.Major != right.Major {
		if left.Major > right.Major {
			return 1
		}

		return -1
	}

	if left.Minor != right.Minor {
		if left.Minor > right.Minor {
			return 1
		}

		return -1
	}

	if left.Patch != right.Patch {
		if left.Patch > right.Patch {
			return 1
		}

		return -1
	}

	if left.Flavor != right.Flavor {
		if left.Flavor > right.Flavor {
			return 1
		}

		return -1
	}

	if left.Name != right.Name {
		if left.Name > right.Name {
			return 1
		}

		return -1
	}

	return 0
}

func selectTagsForCVEListing(tags []registry.Tag, currentTag string) ([]string, string) {
	orderedTags := orderedComparableTags(tags)
	if len(orderedTags) == 0 {
		return nil, ""
	}

	currentIndex := -1
	for index, tagName := range orderedTags {
		if tagName == currentTag {
			currentIndex = index
			break
		}
	}

	if currentIndex == -1 {
		return nil, ""
	}

	previousTag := ""

	previousIndex := currentIndex + 1
	if previousIndex < len(orderedTags) {
		previousTag = orderedTags[previousIndex]
	}

	ordered := make([]string, 0, currentIndex+2)

	// newer tags first (already sorted newest-first by orderedComparableTags)
	for index := 0; index < currentIndex; index++ {
		ordered = append(ordered, orderedTags[index])
	}

	ordered = append(ordered, currentTag)

	if previousTag != "" {
		ordered = append(ordered, previousTag)
	}

	return ordered, previousTag
}

type comparableTag struct {
	Name   string
	Major  int
	Minor  int
	Patch  int
	Build  int
	Flavor string
}

func orderedComparableTags(tags []registry.Tag) []string {
	parsed := make([]comparableTag, 0, len(tags))
	for _, tag := range tags {
		if item, ok := parseComparableTag(tag.Name); ok {
			parsed = append(parsed, item)
		}
	}

	if len(parsed) == 0 {
		return nil
	}

	sort.Slice(parsed, func(i, j int) bool {
		left := parsed[i]
		right := parsed[j]

		if left.Build != right.Build {
			return left.Build > right.Build
		}

		if left.Major != right.Major {
			return left.Major > right.Major
		}

		if left.Minor != right.Minor {
			return left.Minor > right.Minor
		}

		if left.Patch != right.Patch {
			return left.Patch > right.Patch
		}

		if left.Flavor != right.Flavor {
			return left.Flavor > right.Flavor
		}

		return left.Name > right.Name
	})

	seen := make(map[string]struct{}, len(parsed))
	ordered := make([]string, 0, len(parsed))
	for _, tag := range parsed {
		if _, found := seen[tag.Name]; found {
			continue
		}
		seen[tag.Name] = struct{}{}
		ordered = append(ordered, tag.Name)
	}

	return ordered
}

func parseComparableTag(tagName string) (comparableTag, bool) {
	name := strings.TrimSpace(tagName)
	if name == "" {
		return comparableTag{}, false
	}

	lowerName := strings.ToLower(name)
	if strings.HasPrefix(lowerName, "sha256-") {
		return comparableTag{}, false
	}

	if strings.HasSuffix(lowerName, ".sig") || strings.HasSuffix(lowerName, ".att") {
		return comparableTag{}, false
	}

	if !strings.HasPrefix(name, "v") {
		return comparableTag{}, false
	}

	buildMarker := "-build"
	buildIndex := strings.LastIndex(name, buildMarker)
	if buildIndex <= 1 || buildIndex+len(buildMarker) >= len(name) {
		return comparableTag{}, false
	}

	buildValue := name[buildIndex+len(buildMarker):]
	build, err := strconv.Atoi(buildValue)
	if err != nil {
		return comparableTag{}, false
	}

	versionAndFlavor := name[1:buildIndex]
	versionCore := versionAndFlavor
	flavor := ""
	if dashIndex := strings.Index(versionAndFlavor, "-"); dashIndex >= 0 {
		versionCore = versionAndFlavor[:dashIndex]
		flavor = versionAndFlavor[dashIndex+1:]
	}

	versionParts := strings.Split(versionCore, ".")
	if len(versionParts) != 3 {
		return comparableTag{}, false
	}

	major, err := strconv.Atoi(versionParts[0])
	if err != nil {
		return comparableTag{}, false
	}

	minor, err := strconv.Atoi(versionParts[1])
	if err != nil {
		return comparableTag{}, false
	}

	patch, err := strconv.Atoi(versionParts[2])
	if err != nil {
		return comparableTag{}, false
	}

	return comparableTag{
		Name:   name,
		Major:  major,
		Minor:  minor,
		Patch:  patch,
		Build:  build,
		Flavor: flavor,
	}, true
}

func printImageListWithCVEs(component components.Component, tagsToScan []string, currentTag string, previousTag string, cveByTag map[string]cveListEntry, verbose bool) {
	fmt.Printf("COMPONENT:  %s\n", component.Name)
	fmt.Printf("REPOSITORY: %s\n\n", component.Repository)
	fmt.Printf("%-24s %-10s %-10s %s\n", "TAG", "STATUS", "CVE COUNT", "VULNERABILITIES")

	for _, tagName := range tagsToScan {
		status := "NEWER"
		switch tagName {
		case currentTag:
			status = "CURRENT*"
		case previousTag:
			status = "PREVIOUS"
		}

		count, vulnerabilities := renderCVESummary(cveByTag[tagName], verbose)
		fmt.Printf("%-24s %-10s %-10s %s\n", tagName, status, count, vulnerabilities)
	}
}

func renderCVESummary(entry cveListEntry, verbose bool) (string, string) {
	if strings.TrimSpace(entry.Error) != "" {
		message := strings.TrimSpace(entry.Error)
		if !verbose {
			message = truncateText(message, 80)
		}
		return "ERR", "scan error: " + message
	}

	if len(entry.CVEs) == 0 {
		return "0", "none"
	}

	count := fmt.Sprintf("%d", len(entry.CVEs))
	if verbose {
		return count, strings.Join(entry.CVEs, ", ")
	}

	if len(entry.CVEs) <= 2 {
		return count, strings.Join(entry.CVEs, ", ")
	}

	return count, fmt.Sprintf("%s...", strings.Join(entry.CVEs[:2], ", "))
}

func truncateText(value string, maxLength int) string {
	if maxLength <= 0 {
		return ""
	}

	if len(value) <= maxLength {
		return value
	}

	if maxLength <= 3 {
		return value[:maxLength]
	}

	return value[:maxLength-3] + "..."
}

// printUsage prints a help menu describing how the tool must be used
func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  rke2-patcher --version")
	fmt.Println("  rke2-patcher image-cve <component>")
	fmt.Println("  rke2-patcher image-list <component> [--with-cves] [--verbose]")
	fmt.Println("  rke2-patcher image-patch <component> [--dry-run] [--revert]")
	fmt.Println()
	fmt.Printf("Supported components: %s\n", strings.Join(components.Supported(), ", "))
	fmt.Println()
	fmt.Println("Environment variables:")
	fmt.Println("  KUBECONFIG                         kubeconfig path (first file in list is used)")
	fmt.Println("  RKE2_PATCHER_REGISTRY              registry base URL (default: registry.rancher.com)")
	fmt.Println("  RKE2_PATCHER_DATA_DIR              path to RKE2 data directory")
	fmt.Println("  RKE2_PATCHER_CACHE_DIR             path to cache directory for patch-limit state")
	fmt.Println("  RKE2_PATCHER_HELM_NAMESPACE        Helm namespace override")
	fmt.Println("  RKE2_PATCHER_CVE_MODE              CVE scanner mode (cluster|local)")
	fmt.Println("  RKE2_PATCHER_CVE_NAMESPACE         namespace for the CVE scanner job")
	fmt.Println("  RKE2_PATCHER_CVE_SCANNER_IMAGE     Trivy scanner image to use")
	fmt.Println("  RKE2_PATCHER_CVE_JOB_TIMEOUT       timeout for the CVE scanner job (e.g. 5m)")
}

// printVersion prints the version of the tool and the version of the RKE2 cluster
func printVersion() {
	fmt.Printf("rke2-patcher %s\n", version)

	clusterVersion, err := kube.ClusterVersion()
	if err != nil {
		fmt.Printf("cluster version: unavailable (%v)\n", err)
		return
	}

	fmt.Printf("cluster version: %s\n", clusterVersion)
}
