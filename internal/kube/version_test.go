package kube

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClusterVersion(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		body        string
		wantVersion string
		wantErr     string
	}{
		{
			name:        "returns gitVersion on success",
			statusCode:  http.StatusOK,
			body:        `{"gitVersion":"v1.32.2+rke2r1"}`,
			wantVersion: "v1.32.2+rke2r1",
		},
		{
			name:       "returns error when status is not ok",
			statusCode: http.StatusUnauthorized,
			body:       `{"message":"unauthorized"}`,
			wantErr:    "failed to fetch cluster version",
		},
		{
			name:       "returns error when gitVersion is missing",
			statusCode: http.StatusOK,
			body:       `{"major":"1","minor":"32"}`,
			wantErr:    "did not include gitVersion",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			authSeen := ""
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				authSeen = request.Header.Get("Authorization")
				if request.URL.Path != "/version" {
					writer.WriteHeader(http.StatusNotFound)
					_, _ = writer.Write([]byte(`{"message":"not found"}`))
					return
				}

				writer.WriteHeader(testCase.statusCode)
				_, _ = writer.Write([]byte(testCase.body))
			}))
			defer server.Close()

			api := kubeAPI{
				Client:     server.Client(),
				BaseURL:    server.URL,
				AuthHeader: "Bearer test-token",
			}

			gotVersion, err := clusterVersion(api)

			if authSeen != "Bearer test-token" {
				t.Fatalf("expected authorization header to be set, got %q", authSeen)
			}

			if testCase.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", testCase.wantErr)
				}
				if !strings.Contains(err.Error(), testCase.wantErr) {
					t.Fatalf("expected error containing %q, got %q", testCase.wantErr, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			if gotVersion != testCase.wantVersion {
				t.Fatalf("expected version %q, got %q", testCase.wantVersion, gotVersion)
			}
		})
	}
}

func TestClusterVersionRequestCreationFailure(t *testing.T) {
	api := kubeAPI{
		Client:  &http.Client{},
		BaseURL: string([]byte{0x7f}),
	}

	_, err := clusterVersion(api)
	if err == nil {
		t.Fatalf("expected request creation error, got nil")
	}

	if !strings.Contains(strings.ToLower(fmt.Sprintf("%v", err)), "invalid") {
		t.Fatalf("expected invalid url error, got %v", err)
	}
}
