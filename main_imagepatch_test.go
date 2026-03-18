package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/manuelbuil/PoCs/2026/rke2-patcher/internal/registry"
)

func TestParseImagePatchOptions(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		expected     imagePatchOptions
		errContains  string
		errContains2 string
	}{
		{
			name:     "no options",
			args:     nil,
			expected: imagePatchOptions{},
		},
		{
			name: "dry run and revert",
			args: []string{"--dry-run", "--revert"},
			expected: imagePatchOptions{
				DryRun: true,
				Revert: true,
			},
		},
		{
			name:         "unsupported option",
			args:         []string{"--unknown"},
			errContains:  "unsupported image-patch option",
			errContains2: "--unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options, err := parseImagePatchOptions(tt.args)
			if tt.errContains != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.errContains)
				}
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Fatalf("expected error containing %q, got %q", tt.errContains, err.Error())
				}
				if tt.errContains2 != "" && !strings.Contains(err.Error(), tt.errContains2) {
					t.Fatalf("expected error containing %q, got %q", tt.errContains2, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !reflect.DeepEqual(options, tt.expected) {
				t.Fatalf("unexpected options: %#v", options)
			}
		})
	}
}

func TestEnsureManifestsDirectoryExists(t *testing.T) {
	t.Run("existing directory", func(t *testing.T) {
		tempDir := t.TempDir()
		filePath := filepath.Join(tempDir, "manifest.yaml")

		if err := ensureManifestsDirectoryExists(filePath); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("missing directory", func(t *testing.T) {
		tempDir := t.TempDir()
		filePath := filepath.Join(tempDir, "missing", "manifest.yaml")

		err := ensureManifestsDirectoryExists(filePath)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "does not exist") {
			t.Fatalf("expected does not exist error, got %q", err.Error())
		}
		if !strings.Contains(err.Error(), "RKE2_PATCHER_DATA_DIR") {
			t.Fatalf("expected suggestion to use RKE2_PATCHER_DATA_DIR, got %q", err.Error())
		}
	})

	t.Run("manifests path is not a directory", func(t *testing.T) {
		tempDir := t.TempDir()
		notDir := filepath.Join(tempDir, "not-a-dir")
		if err := os.WriteFile(notDir, []byte("x"), 0644); err != nil {
			t.Fatalf("failed writing file: %v", err)
		}

		filePath := filepath.Join(notDir, "manifest.yaml")
		err := ensureManifestsDirectoryExists(filePath)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "is not a directory") {
			t.Fatalf("expected not a directory error, got %q", err.Error())
		}
		if !strings.Contains(err.Error(), "RKE2_PATCHER_DATA_DIR") {
			t.Fatalf("expected suggestion to use RKE2_PATCHER_DATA_DIR, got %q", err.Error())
		}
	})
}

func TestParseComparableTag(t *testing.T) {
	t.Run("version build tag", func(t *testing.T) {
		tag, ok := parseComparableTag("v1.14.1-build20260206")
		if !ok {
			t.Fatalf("expected tag to be parseable")
		}

		if tag.Major != 1 || tag.Minor != 14 || tag.Patch != 1 || tag.Build != 20260206 {
			t.Fatalf("unexpected parsed tag: %#v", tag)
		}
	})

	t.Run("lts build tag", func(t *testing.T) {
		tag, ok := parseComparableTag("v1.12.0-lts1-build20250210")
		if !ok {
			t.Fatalf("expected lts tag to be parseable")
		}

		if tag.Flavor != "lts1" {
			t.Fatalf("unexpected flavor: %q", tag.Flavor)
		}
	})

	t.Run("signature tag excluded", func(t *testing.T) {
		if _, ok := parseComparableTag("sha256-1234.sig"); ok {
			t.Fatalf("expected signature tag to be excluded")
		}
	})
}

func TestSelectTagsForCVEListing_OrderedAndFiltered(t *testing.T) {
	tags := []registry.Tag{
		{Name: "sha256-063f303c.att"},
		{Name: "sha256-063f303c.sig"},
		{Name: "v1.10.1-build20230406"},
		{Name: "v1.12.4-build20251015"},
		{Name: "v1.14.1-build20260203"},
		{Name: "v1.14.1-build20260206"},
		{Name: "v1.14.2-build20260309"},
	}

	ordered, previous := selectTagsForCVEListing(tags, "v1.14.1-build20260206")

	expectedOrdered := []string{
		"v1.14.2-build20260309",
		"v1.14.1-build20260206",
		"v1.14.1-build20260203",
	}

	if !reflect.DeepEqual(ordered, expectedOrdered) {
		t.Fatalf("unexpected ordered tags: %#v", ordered)
	}

	if previous != "v1.14.1-build20260203" {
		t.Fatalf("unexpected previous tag: %q", previous)
	}
}

func TestOrderedComparableTags(t *testing.T) {
	tags := []registry.Tag{
		{Name: "v1.14.1-build20260206"},
		{Name: "v1.14.2-build20260309"},
		{Name: "v1.14.1-build20260203"},
		{Name: "sha256-1234.att"},
	}

	ordered := orderedComparableTags(tags)
	expected := []string{
		"v1.14.2-build20260309",
		"v1.14.1-build20260206",
		"v1.14.1-build20260203",
	}

	if !reflect.DeepEqual(ordered, expected) {
		t.Fatalf("unexpected ordered tags: %#v", ordered)
	}
}
