package cmd

import (
	"fmt"
	"strings"

	"github.com/manuelbuil/PoCs/2026/rke2-patcher/internal/components"
)

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

func printPatchPreview(componentName, runningImage, currentTag, targetTag, filePath, content string) {
	fmt.Printf("component: %s\n", componentName)
	fmt.Printf("current image: %s\n", runningImage)
	fmt.Printf("current tag: %s\n", currentTag)
	fmt.Printf("new tag: %s\n", targetTag)
	fmt.Printf("dry-run: true\n")
	fmt.Printf("would write HelmChartConfig: %s\n", filePath)
	fmt.Println("---")
	fmt.Print(content)
}

func printPatchApplied(componentName, runningImage, currentTag, targetTag, filePath string) {
	fmt.Printf("component: %s\n", componentName)
	fmt.Printf("current image: %s\n", runningImage)
	fmt.Printf("current tag: %s\n", currentTag)
	fmt.Printf("new tag: %s\n", targetTag)
	fmt.Printf("wrote HelmChartConfig: %s\n", filePath)
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

func printReconcileApplied(entry patchLimitEntry) {
	fmt.Printf("reconcile: component %s: stripped patcher overrides (was pinned to %s on RKE2 %s)\n", components.CLIName(entry.Component), entry.PatchedToTag, entry.ClusterVersion)
}

func printReconcileAlreadyCurrent(componentName string) {
	fmt.Printf("reconcile: component %s: no stale patches found; already up to date\n", componentName)
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
