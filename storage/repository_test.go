package storage

import "testing"

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "lowercases and trims trailing dot",
			input: " Sub.Example-Domain.Tld. ",
			want:  "sub.example-domain.tld",
		},
		{
			name:    "rejects two character label",
			input:   "ab.example.tld",
			wantErr: true,
		},
		{
			name:    "rejects leading hyphen",
			input:   "-sub.example.tld",
			wantErr: true,
		},
		{
			name:    "rejects trailing hyphen",
			input:   "sub-.example.tld",
			wantErr: true,
		},
		{
			name:    "rejects underscore",
			input:   "sub_domain.example.tld",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeDomain(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("NormalizeDomain(%q) expected error", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeDomain(%q) unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("NormalizeDomain(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeFingerprint(t *testing.T) {
	got, err := normalizeFingerprint("AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99")
	if err != nil {
		t.Fatalf("normalizeFingerprint unexpected error: %v", err)
	}

	want := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	if got != want {
		t.Fatalf("normalizeFingerprint = %q, want %q", got, want)
	}

	if _, err := normalizeFingerprint("not-a-sha256"); err == nil {
		t.Fatal("normalizeFingerprint expected error for invalid fingerprint")
	}
}
