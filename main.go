package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/manuelbuil/PoCs/2026/rke2-patcher/internal/components"
	"github.com/manuelbuil/PoCs/2026/rke2-patcher/internal/cve"
	"github.com/manuelbuil/PoCs/2026/rke2-patcher/internal/dockerhub"
	"github.com/manuelbuil/PoCs/2026/rke2-patcher/internal/kube"
	"github.com/manuelbuil/PoCs/2026/rke2-patcher/internal/patcher"
)

const version = "0.2.8"

type imageListOptions struct {
	WithCVEs bool
	Verbose  bool
}

type cveListEntry struct {
	CVEs  []string
	Error string
}

type imagePatchOptions struct {
	DryRun  bool
	Revert  bool
	DataDir string
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
		scannerMode, parseErr := parseImageCVEOptions(extraArgs)
		if parseErr != nil {
			log.Printf("%v", parseErr)
			printUsage()
			os.Exit(2)
		}
		if err := runCVE(component, scannerMode); err != nil {
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

// parseImageCVEOptions parses and validates the scanner mode option
func parseImageCVEOptions(args []string) (string, error) {
	if len(args) == 0 {
		return "", nil
	}

	scannerMode := ""

	for i := 0; i < len(args); i++ {
		arg := strings.TrimSpace(args[i])
		switch {
		case strings.HasPrefix(arg, "--scanner-mode="):
			if scannerMode != "" {
				return "", fmt.Errorf("duplicate --scanner-mode option")
			}
			scannerMode = strings.TrimSpace(strings.TrimPrefix(arg, "--scanner-mode="))
			if scannerMode == "" {
				return "", fmt.Errorf("--scanner-mode requires a value: cluster or local")
			}
		case arg == "--scanner-mode":
			if scannerMode != "" {
				return "", fmt.Errorf("duplicate --scanner-mode option")
			}
			i++
			if i >= len(args) {
				return "", fmt.Errorf("--scanner-mode requires a value: cluster or local")
			}
			scannerMode = strings.TrimSpace(args[i])
			if scannerMode == "" {
				return "", fmt.Errorf("--scanner-mode requires a value: cluster or local")
			}
		default:
			return "", fmt.Errorf("unsupported image-cve option(s): %s", strings.Join(args, " "))
		}
	}

	return scannerMode, nil
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
		case strings.HasPrefix(arg, "--data-dir="):
			if options.DataDir != "" {
				return imagePatchOptions{}, fmt.Errorf("duplicate --data-dir option")
			}
			value := strings.TrimSpace(strings.TrimPrefix(arg, "--data-dir="))
			if value == "" {
				return imagePatchOptions{}, fmt.Errorf("--data-dir requires a value")
			}
			options.DataDir = value
		case arg == "--data-dir":
			if options.DataDir != "" {
				return imagePatchOptions{}, fmt.Errorf("duplicate --data-dir option")
			}
			i++
			if i >= len(args) {
				return imagePatchOptions{}, fmt.Errorf("--data-dir requires a value")
			}

			value := strings.TrimSpace(args[i])
			if value == "" {
				return imagePatchOptions{}, fmt.Errorf("--data-dir requires a value")
			}
			options.DataDir = value
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

func runCVE(component components.Component, scannerMode string) error {
	if err := kube.EnsureAnyWorkloadExists(component.Workloads); err != nil {
		return err
	}

	runningImages, err := listRunningImagesForComponent(component)
	if err != nil {
		return err
	}

	image := runningImages[0].Image
	effectiveScannerMode, err := cve.ResolveScanMode(scannerMode)
	if err != nil {
		return err
	}
	log.Printf("scanner mode: %s", effectiveScannerMode)

	result, err := cve.ListForImageWithMode(image, effectiveScannerMode)
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
	runningImages, err := listRunningImagesForComponent(component)
	if err != nil {
		return fmt.Errorf("running image unavailable: %w", err)
	}

	if options.WithCVEs {
		currentImage := runningImages[0].Image
		currentImageName, currentTag := kube.SplitImage(currentImage)
		if currentTag == "" {
			return fmt.Errorf("running image %q does not include a tag", currentImage)
		}

		tagsForSelection, err := dockerhub.ListTags(component.DockerHubRepository, 200)
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

		resultsByImage, errorsByImage, scanErr := cve.ListForImagesInCluster(targetImages)
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

		printImageListWithCVEs(component, tagsForSelection, tagsToScan, currentTag, previousTag, cveByTag, options.Verbose)
		return nil
	}

	currentImage := runningImages[0].Image
	_, currentTag := kube.SplitImage(currentImage)
	if currentTag == "" {
		return fmt.Errorf("running image %q does not include a tag", currentImage)
	}

	tagsForSelection, err := dockerhub.ListTags(component.DockerHubRepository, 200)
	if err != nil {
		return err
	}

	tagsToShow, _ := selectTagsForCVEListing(tagsForSelection, currentTag)
	if len(tagsToShow) == 0 {
		return fmt.Errorf("failed to determine tags to show for current tag %q", currentTag)
	}

	tagInfoByName := make(map[string]dockerhub.Tag, len(tagsForSelection))
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
	fmt.Printf("repository: %s\n", component.DockerHubRepository)
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
	if err := kube.EnsureAnyWorkloadExists(component.Workloads); err != nil {
		return err
	}

	runningImages, err := listRunningImagesForComponent(component)
	if err != nil {
		return err
	}

	runningImage := runningImages[0].Image
	currentImageName, currentImageTag := kube.SplitImage(runningImage)

	targetTagName, err := resolvePatchTargetTag(component.DockerHubRepository, currentImageTag, options.Revert)
	if err != nil {
		return err
	}

	filePath, generatedContent := patcher.BuildHelmChartConfigWithDataDir(component.Name, component.HelmChartConfigName, currentImageName, targetTagName, options.DataDir)

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

	fmt.Printf("component: %s\n", component.Name)
	fmt.Printf("current image: %s\n", runningImage)
	fmt.Printf("current tag: %s\n", currentImageTag)
	fmt.Printf("new tag: %s\n", targetTagName)
	fmt.Printf("wrote HelmChartConfig: %s\n", filePath)

	return nil
}

func ensureManifestsDirectoryExists(filePath string) error {
	manifestsDir := strings.TrimSpace(filepath.Dir(filePath))
	if manifestsDir == "" {
		return fmt.Errorf("failed to resolve manifests directory from output path %q; use --data-dir <path> (for example /var/lib/rancher/rke2)", filePath)
	}

	info, err := os.Stat(manifestsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("manifests directory %q does not exist; use --data-dir <path> to point to the RKE2 data directory", manifestsDir)
		}

		return fmt.Errorf("failed to verify manifests directory %q: %w", manifestsDir, err)
	}

	if !info.IsDir() {
		return fmt.Errorf("manifests path %q is not a directory; use --data-dir <path> to point to the RKE2 data directory", manifestsDir)
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
	tags, err := dockerhub.ListTags(repository, 200)
	if err != nil {
		return "", fmt.Errorf("failed to list tags: %w", err)
	}

	currentIndex := -1
	for index, tag := range tags {
		if tag.Name == currentTag && currentIndex == -1 {
			currentIndex = index
		}
	}

	if currentIndex == -1 {
		return "", fmt.Errorf("refusing to patch: current tag %q not found in latest observed tags", currentTag)
	}

	if revert {
		targetIndex := currentIndex + 1
		if targetIndex >= len(tags) {
			return "", fmt.Errorf("refusing to revert: current tag %q is already the oldest available in the observed tag list", currentTag)
		}
		return tags[targetIndex].Name, nil
	}

	targetIndex := currentIndex - 1
	if targetIndex < 0 {
		return "", fmt.Errorf("refusing to patch: current tag %q is already the latest", currentTag)
	}

	return tags[targetIndex].Name, nil
}

func listRunningImagesForComponent(component components.Component) ([]kube.PodImageSummary, error) {
	if len(component.Workloads) == 0 {
		return kube.ListRunningImagesByRepository(component.DockerHubRepository)
	}

	return kube.ListRunningImagesForWorkloadsByRepository(component.Workloads, component.DockerHubRepository)
}

func selectTagsForCVEListing(tags []dockerhub.Tag, currentTag string) ([]string, string) {
	if len(tags) == 0 {
		return nil, ""
	}

	currentIndex := -1
	for index, tag := range tags {
		if tag.Name == currentTag {
			currentIndex = index
			break
		}
	}

	if currentIndex == -1 {
		return nil, ""
	}

	selected := make(map[string]struct{})
	selected[currentTag] = struct{}{}
	previousTag := ""

	previousIndex := currentIndex + 1
	if previousIndex < len(tags) {
		previousTag = tags[previousIndex].Name
		selected[previousTag] = struct{}{}
	}

	for index := 0; index < currentIndex; index++ {
		selected[tags[index].Name] = struct{}{}
	}

	ordered := make([]string, 0, len(selected))
	for _, tag := range tags {
		if _, found := selected[tag.Name]; found {
			ordered = append(ordered, tag.Name)
		}
	}

	return ordered, previousTag
}

func printImageListWithCVEs(component components.Component, tags []dockerhub.Tag, tagsToScan []string, currentTag string, previousTag string, cveByTag map[string]cveListEntry, verbose bool) {
	tagInfoByName := make(map[string]dockerhub.Tag, len(tags))
	for _, tag := range tags {
		tagInfoByName[tag.Name] = tag
	}

	fmt.Printf("COMPONENT:  %s\n", component.Name)
	fmt.Printf("REPOSITORY: %s\n\n", component.DockerHubRepository)
	fmt.Printf("%-24s %-10s %-12s %-10s %s\n", "TAG", "STATUS", "UPDATED", "CVE COUNT", "VULNERABILITIES")

	for _, tagName := range tagsToScan {
		status := "NEWER"
		switch tagName {
		case currentTag:
			status = "CURRENT*"
		case previousTag:
			status = "PREVIOUS"
		}

		updated := "-"
		if tagInfo, found := tagInfoByName[tagName]; found && !tagInfo.LastUpdated.IsZero() {
			updated = tagInfo.LastUpdated.Format("2006-01-02")
		}

		count, vulnerabilities := renderCVESummary(cveByTag[tagName], verbose)
		fmt.Printf("%-24s %-10s %-12s %-10s %s\n", tagName, status, updated, count, vulnerabilities)
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
	fmt.Println("  rke2-patcher image-cve <component> [--scanner-mode cluster|local]")
	fmt.Println("  rke2-patcher image-list <component> [--with-cves] [--verbose]")
	fmt.Println("  rke2-patcher image-patch <component> [--dry-run] [--revert] [--data-dir <path>]")
	fmt.Println()
	fmt.Printf("Supported components: %s\n", strings.Join(components.Supported(), ", "))
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
