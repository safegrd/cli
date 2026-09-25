package model

import (
	"testing"
)

func TestIsVersionOutdated(t *testing.T) {
	tests := []struct {
		current string
		latest  string
		want    bool
	}{
		{"0.1.0", "0.2.0", true},
		{"v0.1.0", "0.2.0", true},
		{"0.1.0", "v0.2.0", true},
		{"1.0.0", "2.0.0", true},
		{"1.0.0", "1.0.1", true},
		{"1.1.0", "1.1.0", false},
		{"1.2.0", "1.1.0", false},
		{"2.0.0", "1.9.9", false},
		{"dev", "1.0.0", false},
		{"1.0.0", "dev", false},
		{"", "1.0.0", false},
		{"1.0.0", "", false},
		{"unknown", "1.0.0", false},
		{"1.0.0-rc1", "1.0.0", false},
		{"0.9.0-rc1", "1.0.0", true},
	}

	for _, tc := range tests {
		got := IsVersionOutdated(tc.current, tc.latest)
		if got != tc.want {
			t.Errorf("IsVersionOutdated(%q, %q) = %v, want %v", tc.current, tc.latest, got, tc.want)
		}
	}
}
