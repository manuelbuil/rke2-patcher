package kube

import "testing"

func TestHostnameCandidates(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{
			name: "empty",
			in:   "",
			want: nil,
		},
		{
			name: "simple hostname",
			in:   "ip-10-11-0-13",
			want: []string{"ip-10-11-0-13"},
		},
		{
			name: "fqdn",
			in:   "ip-10-11-0-13.ec2.internal",
			want: []string{"ip-10-11-0-13.ec2.internal", "ip-10-11-0-13"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hostnameCandidates(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("hostnameCandidates() len = %d, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("hostnameCandidates()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestAnnotationMatchesLocalIdentity(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		hostnames   []string
		ips         map[string]struct{}
		want        bool
	}{
		{
			name: "matches by hostname",
			annotations: map[string]string{
				rke2HostnameAnnotationKey: "ip-10-11-0-13",
			},
			hostnames: []string{"ip-10-11-0-13"},
			ips:       map[string]struct{}{},
			want:      true,
		},
		{
			name: "matches by internal ip",
			annotations: map[string]string{
				rke2InternalIPAnnotationKey: "10.11.0.13,2a05:d011:18:7101:e9e3:938c:c796:36e8",
			},
			hostnames: []string{"other-host"},
			ips: map[string]struct{}{
				"10.11.0.13": {},
			},
			want: true,
		},
		{
			name: "no match",
			annotations: map[string]string{
				rke2HostnameAnnotationKey:   "ip-10-11-0-13",
				rke2InternalIPAnnotationKey: "10.11.0.13",
			},
			hostnames: []string{"different-host"},
			ips: map[string]struct{}{
				"192.168.1.1": {},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := annotationMatchesLocalIdentity(tt.annotations, tt.hostnames, tt.ips)
			if got != tt.want {
				t.Fatalf("annotationMatchesLocalIdentity() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseDataDirFromNodeArgs(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		wantValue string
		wantFound bool
		wantErr   bool
	}{
		{
			name:      "empty annotation",
			raw:       "",
			wantValue: "",
			wantFound: false,
			wantErr:   false,
		},
		{
			name:      "long flag separate value",
			raw:       `["server","--data-dir","/var/lib/testing/rke2"]`,
			wantValue: "/var/lib/testing/rke2",
			wantFound: true,
			wantErr:   false,
		},
		{
			name:      "long flag equals value",
			raw:       `["server","--data-dir=/var/lib/testing/rke2"]`,
			wantValue: "/var/lib/testing/rke2",
			wantFound: true,
			wantErr:   false,
		},
		{
			name:      "short flag separate value",
			raw:       `["server","-d","/var/lib/testing/rke2"]`,
			wantValue: "/var/lib/testing/rke2",
			wantFound: true,
			wantErr:   false,
		},
		{
			name:      "short flag equals value",
			raw:       `["server","-d=/var/lib/testing/rke2"]`,
			wantValue: "/var/lib/testing/rke2",
			wantFound: true,
			wantErr:   false,
		},
		{
			name:      "missing value",
			raw:       `["server","--data-dir"]`,
			wantValue: "",
			wantFound: false,
			wantErr:   true,
		},
		{
			name:      "invalid json",
			raw:       `["server",`,
			wantValue: "",
			wantFound: false,
			wantErr:   true,
		},
		{
			name:      "no data-dir present",
			raw:       `["server","--write-kubeconfig-mode","644"]`,
			wantValue: "",
			wantFound: false,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotValue, gotFound, err := parseDataDirFromNodeArgs(tt.raw)

			if (err != nil) != tt.wantErr {
				t.Fatalf("parseDataDirFromNodeArgs() error = %v, wantErr %v", err, tt.wantErr)
			}

			if gotFound != tt.wantFound {
				t.Fatalf("parseDataDirFromNodeArgs() found = %v, want %v", gotFound, tt.wantFound)
			}

			if gotValue != tt.wantValue {
				t.Fatalf("parseDataDirFromNodeArgs() value = %q, want %q", gotValue, tt.wantValue)
			}
		})
	}
}
