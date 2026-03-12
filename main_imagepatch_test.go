package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
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
			name: "data dir separate value",
			args: []string{"--data-dir", "/var/lib/rancher/rke2-custom"},
			expected: imagePatchOptions{
				DataDir: "/var/lib/rancher/rke2-custom",
			},
		},
		{
			name: "data dir equals value",
			args: []string{"--data-dir=/var/lib/rancher/rke2-custom"},
			expected: imagePatchOptions{
				DataDir: "/var/lib/rancher/rke2-custom",
			},
		},
		{
			name:        "duplicate data dir",
			args:        []string{"--data-dir=/tmp/a", "--data-dir", "/tmp/b"},
			errContains: "duplicate --data-dir option",
		},
		{
			name:        "data dir missing value",
			args:        []string{"--data-dir"},
			errContains: "--data-dir requires a value",
		},
		{
			name:        "data dir empty equals value",
			args:        []string{"--data-dir="},
			errContains: "--data-dir requires a value",
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
		if !strings.Contains(err.Error(), "--data-dir <path>") {
			t.Fatalf("expected suggestion to use --data-dir, got %q", err.Error())
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
		if !strings.Contains(err.Error(), "--data-dir <path>") {
			t.Fatalf("expected suggestion to use --data-dir, got %q", err.Error())
		}
	})
}
