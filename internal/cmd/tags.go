package cmd

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/manuelbuil/rke2-patcher/internal/registry"
)

type comparableTag struct {
	Name   string
	Major  int
	Minor  int
	Patch  int
	Build  int
	Flavor string //hardened or empty
}

// orderedComparableTags takes raw registry tags, parses and sorts them from newest to oldest based on comparableTag fields
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

// parseComparableTag breaks a tag into the comparableTag struct
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

// compareComparableTags compares two comparableTag items and returns an integer indicating their relative order (newer vs older)
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

func isNewerMinorRelease(current comparableTag, target comparableTag) bool {
	if target.Major != current.Major {
		return target.Major > current.Major
	}
	return target.Minor > current.Minor
}

// selectTagsForCVEListing prepares a curated list. Only one previous and all the new tags but ordered
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

// resolvePatchTargetTag finds the target tag to patch to after going through the different limitations checks
func resolvePatchTargetTag(repository string, currentTag string) (string, error) {
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
