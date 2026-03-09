package cve

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/manuelbuil/PoCs/2026/rke2-patcher/internal/kube"
)

const cveModeEnv = "RKE2_PATCHER_CVE_MODE"

const (
	batchScanBeginPrefix = "__RKE2_PATCHER_TRIVY_BEGIN__"
	batchScanRCPrefix    = "__RKE2_PATCHER_TRIVY_RC__"
	batchScanEndPrefix   = "__RKE2_PATCHER_TRIVY_END__"
	vexReportURL         = "https://raw.githubusercontent.com/rancher/vexhub/refs/heads/main/reports/rancher.openvex.json"
	vexFileName          = "rancher.openvex.json"
	vexDownloadAttempts  = 3
)

type Result struct {
	Tool string
	CVEs []string
}

func ListForImage(image string) (Result, error) {
	return ListForImageWithMode(image, "")
}

func ResolveScanMode(modeOverride string) (string, error) {
	return resolveScanMode(modeOverride)
}

func ListForImagesInCluster(images []string) (map[string]Result, map[string]error, error) {
	targetImages := make([]string, 0, len(images))
	for _, image := range images {
		trimmed := strings.TrimSpace(image)
		if trimmed == "" {
			continue
		}
		targetImages = append(targetImages, trimmed)
	}

	if len(targetImages) == 0 {
		return map[string]Result{}, map[string]error{}, nil
	}

	output, err := kube.ScanImagesWithTrivyJob(targetImages, true)
	if err != nil {
		return nil, nil, fmt.Errorf("cluster scanner failed: %w", err)
	}

	results := make(map[string]Result)
	errorsByImage := make(map[string]error)
	chunksByImage := make(map[string][]string)
	rcByImage := make(map[string]int)

	currentImage := ""
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, batchScanBeginPrefix):
			currentImage = strings.TrimSpace(strings.TrimPrefix(line, batchScanBeginPrefix))
			if _, found := chunksByImage[currentImage]; !found {
				chunksByImage[currentImage] = make([]string, 0)
			}
		case strings.HasPrefix(line, batchScanRCPrefix):
			rest := strings.TrimSpace(strings.TrimPrefix(line, batchScanRCPrefix))
			separator := strings.LastIndex(rest, "__")
			if separator <= 0 {
				return nil, nil, fmt.Errorf("invalid batch scan marker: %q", line)
			}

			image := strings.TrimSpace(rest[:separator])
			rcText := strings.TrimSpace(rest[separator+2:])
			rc, parseErr := strconv.Atoi(rcText)
			if parseErr != nil {
				return nil, nil, fmt.Errorf("invalid batch scan rc marker %q: %w", line, parseErr)
			}
			rcByImage[image] = rc
		case strings.HasPrefix(line, batchScanEndPrefix):
			image := strings.TrimSpace(strings.TrimPrefix(line, batchScanEndPrefix))
			if currentImage == image {
				currentImage = ""
			}
		default:
			if currentImage != "" {
				chunksByImage[currentImage] = append(chunksByImage[currentImage], line)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}

	for _, image := range targetImages {
		rc, found := rcByImage[image]
		if !found {
			errorsByImage[image] = fmt.Errorf("missing scan result from batch job")
			continue
		}

		rawOutput := strings.TrimSpace(strings.Join(chunksByImage[image], "\n"))
		if rc != 0 {
			if rawOutput == "" {
				errorsByImage[image] = fmt.Errorf("trivy exited with code %d", rc)
			} else {
				errorsByImage[image] = fmt.Errorf("%s", rawOutput)
			}
			continue
		}

		cves, parseErr := trivyCVEsFromJSON([]byte(rawOutput))
		if parseErr != nil {
			errorsByImage[image] = fmt.Errorf("failed to parse trivy output: %w", parseErr)
			continue
		}

		results[image] = Result{Tool: "trivy-job-batch", CVEs: cves}
	}

	return results, errorsByImage, nil
}

func ListForImageWithMode(image string, modeOverride string) (Result, error) {
	mode, err := resolveScanMode(modeOverride)
	if err != nil {
		return Result{}, err
	}

	errorsByMode := make([]string, 0)

	if mode == "cluster" {
		output, scanErr := kube.ScanImageWithTrivyJob(image, mode == "cluster")
		if scanErr == nil {
			cves, parseErr := trivyCVEsFromJSON(output)
			if parseErr == nil {
				return Result{Tool: "trivy-job", CVEs: cves}, nil
			}
			scanErr = parseErr
		}

		errorsByMode = append(errorsByMode, fmt.Sprintf("cluster scanner failed: %v", scanErr))
		return Result{}, fmt.Errorf("%s", strings.Join(errorsByMode, "; "))
	}

	if mode == "local" {
		if _, lookErr := exec.LookPath("trivy"); lookErr == nil {
			cves, scanErr := trivyCVEs(image)
			if scanErr == nil {
				return Result{Tool: "trivy", CVEs: cves}, nil
			}
			errorsByMode = append(errorsByMode, fmt.Sprintf("local trivy failed: %v", scanErr))
		}

		if _, lookErr := exec.LookPath("grype"); lookErr == nil {
			cves, scanErr := grypeCVEs(image)
			if scanErr == nil {
				return Result{Tool: "grype", CVEs: cves}, nil
			}
			errorsByMode = append(errorsByMode, fmt.Sprintf("local grype failed: %v", scanErr))
		}

		if len(errorsByMode) == 0 {
			return Result{}, fmt.Errorf("no local scanner available: install trivy or grype")
		}
	}

	if len(errorsByMode) == 0 {
		return Result{}, fmt.Errorf("no scanner available")
	}

	return Result{}, fmt.Errorf("%s", strings.Join(errorsByMode, "; "))
}

func trivyCVEs(image string) ([]string, error) {
	vexFilePath, err := ensureLocalTrivyVEXFile()
	if err != nil {
		return nil, err
	}

	cmd := exec.Command("trivy", "image", "--quiet", "--format", "json", "--severity", "CRITICAL,HIGH", "--vex", vexFilePath, image)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	return trivyCVEsFromJSON(output)
}

func trivyCVEsFromJSON(output []byte) ([]string, error) {

	var report struct {
		Results []struct {
			Vulnerabilities []struct {
				VulnerabilityID string `json:"VulnerabilityID"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}

	if err := json.Unmarshal(output, &report); err != nil {
		return nil, err
	}

	return dedupeCVEs(func(appendCVE func(string)) {
		for _, result := range report.Results {
			for _, vulnerability := range result.Vulnerabilities {
				appendCVE(vulnerability.VulnerabilityID)
			}
		}
	}), nil
}

func ensureLocalTrivyVEXFile() (string, error) {
	homeDirectory, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to resolve user home directory for trivy vex configuration: %w", err)
	}

	vexDirectory := filepath.Join(homeDirectory, ".trivy", "vex")
	if mkdirErr := os.MkdirAll(vexDirectory, 0o755); mkdirErr != nil {
		return "", fmt.Errorf("failed to create trivy vex directory %q: %w", vexDirectory, mkdirErr)
	}

	vexFilePath := filepath.Join(vexDirectory, vexFileName)

	var lastErr error
	for attempt := 1; attempt <= vexDownloadAttempts; attempt++ {
		err = downloadVEXFileOnce(vexDirectory, vexFilePath)
		if err == nil {
			return vexFilePath, nil
		}

		lastErr = err
		if attempt < vexDownloadAttempts {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}

	return "", fmt.Errorf("failed to download vex report from %q after %d attempts: %w", vexReportURL, vexDownloadAttempts, lastErr)
}

func downloadVEXFileOnce(vexDirectory string, vexFilePath string) error {
	response, err := http.Get(vexReportURL)
	if err != nil {
		return fmt.Errorf("download request failed: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		return fmt.Errorf("unexpected status %d: %s", response.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}

	temporaryFile, err := os.CreateTemp(vexDirectory, "rancher.openvex-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temporary vex file: %w", err)
	}
	temporaryFilePath := temporaryFile.Name()
	defer func() {
		_ = os.Remove(temporaryFilePath)
	}()

	if _, copyErr := io.Copy(temporaryFile, response.Body); copyErr != nil {
		_ = temporaryFile.Close()
		return fmt.Errorf("failed to write vex report content to %q: %w", temporaryFilePath, copyErr)
	}

	if closeErr := temporaryFile.Close(); closeErr != nil {
		return fmt.Errorf("failed to close temporary vex file %q: %w", temporaryFilePath, closeErr)
	}

	if renameErr := os.Rename(temporaryFilePath, vexFilePath); renameErr != nil {
		return fmt.Errorf("failed to place vex report at %q: %w", vexFilePath, renameErr)
	}

	return nil
}

func resolveScanMode(modeOverride string) (string, error) {
	mode := strings.ToLower(strings.TrimSpace(modeOverride))
	if mode == "" {
		mode = strings.ToLower(strings.TrimSpace(os.Getenv(cveModeEnv)))
	}
	if mode == "" {
		return "cluster", nil
	}

	switch mode {
	case "cluster", "local":
		return mode, nil
	default:
		return "", fmt.Errorf("invalid %s value %q: expected cluster or local", cveModeEnv, mode)
	}
}

func grypeCVEs(image string) ([]string, error) {
	cmd := exec.Command("grype", image, "-o", "json")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var report struct {
		Matches []struct {
			Vulnerability struct {
				ID string `json:"id"`
			} `json:"vulnerability"`
		} `json:"matches"`
	}

	if err := json.Unmarshal(output, &report); err != nil {
		return nil, err
	}

	return dedupeCVEs(func(appendCVE func(string)) {
		for _, match := range report.Matches {
			appendCVE(match.Vulnerability.ID)
		}
	}), nil
}

func dedupeCVEs(visitor func(func(string))) []string {
	set := make(map[string]struct{})
	visitor(func(value string) {
		id := strings.TrimSpace(value)
		if id == "" {
			return
		}
		set[id] = struct{}{}
	})

	items := make([]string, 0, len(set))
	for id := range set {
		items = append(items, id)
	}
	sort.Strings(items)

	return items
}
