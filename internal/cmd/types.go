package cmd

type imageListOptions struct {
	WithCVEs bool
	Verbose  bool
}

type imagePatchOptions struct {
	DryRun bool
	Revert bool
}

type cveListEntry struct {
	CVEs  []string
	Error string
}

type patchLimitState struct {
	Entries map[string]patchLimitEntry `json:"entries"`
}

type patchLimitEntry struct {
	Component              string `json:"component"`
	ClusterVersion         string `json:"clusterVersion"`
	BaselineTag            string `json:"baselineTag"`
	PatchedToTag           string `json:"patchedToTag"`
	FilePath               string `json:"filePath,omitempty"`
	GeneratedValuesContent string `json:"generatedValuesContent,omitempty"`
}

type patchLimitDecision struct {
	ShouldPersist  bool // when reverting we don't persist it
	StateNamespace string
	EntryKey       string
	Entry          patchLimitEntry
}
