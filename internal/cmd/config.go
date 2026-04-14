package cmd

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/manuelbuil/rke2-patcher/internal/kube"
	cli "github.com/urfave/cli/v2"
)

const (
	registryEnvName         = "RKE2_PATCHER_REGISTRY"
	dataDirEnvName          = "RKE2_PATCHER_DATA_DIR"
	defaultRegistryHost     = "registry.rancher.com"
	cveModeEnvName          = "RKE2_PATCHER_CVE_MODE"
	defaultCVEMode          = "cluster"
	cveNamespaceEnvName     = "RKE2_PATCHER_CVE_NAMESPACE"
	defaultCVENamespaceName = "rke2-patcher"
	cveScannerImageEnvName  = "RKE2_PATCHER_CVE_SCANNER_IMAGE"
	defaultCVEScannerImage  = "aquasec/trivy:0.69.3"
	cveJobTimeoutEnvName    = "RKE2_PATCHER_CVE_JOB_TIMEOUT"
	defaultCVEJobTimeout    = 8 * time.Minute
	defaultRKE2DataDir      = "/var/lib/rancher/rke2"
)

type configEntry struct {
	Key       string
	Effective string
	Default   string
	Source    string
}

func runConfigCommand(ctx *cli.Context) error {
	if ctx.Args().Len() > 0 {
		return cli.Exit(fmt.Sprintf("unexpected extra argument(s): %s", strings.Join(ctx.Args().Slice(), " ")), usageExitCode)
	}

	entries, err := collectConfigEntries()
	if err != nil {
		return err
	}

	fmt.Println("effective configuration:")
	for _, entry := range entries {
		fmt.Printf("- %s: %s (default: %s, source: %s)\n", entry.Key, entry.Effective, entry.Default, entry.Source)
	}

	return nil
}

func collectConfigEntries() ([]configEntry, error) {
	registryValue, registrySource, err := resolveRegistryConfig()
	if err != nil {
		return nil, err
	}

	scannerMode, scannerModeSource, err := resolveScannerModeConfig()
	if err != nil {
		return nil, err
	}

	jobTimeout, timeoutSource, err := resolveDurationConfig(cveJobTimeoutEnvName, defaultCVEJobTimeout)
	if err != nil {
		return nil, err
	}

	dataDir, dataDirSource := envOr(dataDirEnvName, defaultRKE2DataDir)
	cveNamespace, cveNamespaceSource := envOr(cveNamespaceEnvName, defaultCVENamespaceName)
	cveScannerImage, cveScannerImageSource := envOr(cveScannerImageEnvName, defaultCVEScannerImage)

	entries := []configEntry{
		{Key: "registry", Effective: registryValue, Default: "https://" + defaultRegistryHost, Source: registrySource},
		{Key: "scanner_mode", Effective: scannerMode, Default: defaultCVEMode, Source: scannerModeSource},
		{Key: "cve_namespace", Effective: cveNamespace, Default: defaultCVENamespaceName, Source: cveNamespaceSource},
		{Key: "cve_scanner_image", Effective: cveScannerImage, Default: defaultCVEScannerImage, Source: cveScannerImageSource},
		{Key: "cve_job_timeout", Effective: jobTimeout.String(), Default: defaultCVEJobTimeout.String(), Source: timeoutSource},
		{Key: "data_dir", Effective: dataDir, Default: defaultRKE2DataDir, Source: dataDirSource},
		{Key: "manifests_dir", Effective: filepath.Join(dataDir, "server", "manifests"), Default: filepath.Join(defaultRKE2DataDir, "server", "manifests"), Source: dataDirSource},
		{Key: "rke2_patcher_state_configmap", Effective: kube.StateConfigMapName, Default: kube.StateConfigMapName, Source: "default"},
	}

	return entries, nil
}

func resolveRegistryConfig() (string, string, error) {
	rawValue, source := envOr(registryEnvName, defaultRegistryHost)
	if !strings.Contains(rawValue, "://") {
		rawValue = "https://" + rawValue
	}

	parsed, err := url.Parse(rawValue)
	if err != nil {
		return "", "", fmt.Errorf("invalid %s value %q: %w", registryEnvName, rawValue, err)
	}

	scheme := strings.ToLower(strings.TrimSpace(parsed.Scheme))
	if scheme != "https" && scheme != "http" {
		return "", "", fmt.Errorf("invalid %s value %q: scheme must be http or https", registryEnvName, rawValue)
	}
	if strings.TrimSpace(parsed.Host) == "" {
		return "", "", fmt.Errorf("invalid %s value %q: missing registry host", registryEnvName, rawValue)
	}

	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawQuery = ""
	parsed.Fragment = ""

	return parsed.String(), source, nil
}

func resolveScannerModeConfig() (string, string, error) {
	mode, source := envOr(cveModeEnvName, defaultCVEMode)
	mode = strings.ToLower(strings.TrimSpace(mode))
	switch mode {
	case "cluster", "local":
		return mode, source, nil
	default:
		return "", "", fmt.Errorf("invalid %s value %q: expected cluster or local", cveModeEnvName, mode)
	}
}

func resolveDurationConfig(envName string, defaultValue time.Duration) (time.Duration, string, error) {
	raw := strings.TrimSpace(os.Getenv(envName))
	if raw == "" {
		return defaultValue, "default", nil
	}

	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return 0, "", fmt.Errorf("invalid %s value %q: %w", envName, raw, err)
	}
	if parsed <= 0 {
		return 0, "", fmt.Errorf("invalid %s value %q: must be greater than zero", envName, raw)
	}

	return parsed, envName, nil
}

func envOr(name string, defaultValue string) (string, string) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return defaultValue, "default"
	}

	return value, name
}
