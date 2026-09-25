package config

import "testing"

// worm_mode: NONE is an opt-out, and the danger is that it becomes reachable by
// accident. These assert the two properties that keep it deliberate: nothing
// but the exact string NONE resolves to it, and the unset case is unchanged.
func TestWORMModeNoneIsOnlyEverExplicit(t *testing.T) {
	for _, tc := range []struct {
		in      WORMMode
		want    WORMMode
		wantErr bool
	}{
		{"", WORMModeCompliance, false}, // unset is still the strict default
		{WORMModeNone, WORMModeNone, false},
		{WORMModeCompliance, WORMModeCompliance, false},
		{WORMModeGovernance, WORMModeGovernance, false},

		// Near misses must refuse rather than resolve. A config with a typo
		// gets an error naming the valid values.
		{"none", "", true},
		{"None", "", true},
		{"NO", "", true},
		{"OFF", "", true},
		{"DISABLED", "", true},
	} {
		t.Run(string(tc.in)+"/", func(t *testing.T) {
			got, err := (&StorageConfig{WORMMode: tc.in}).ResolveWORMMode()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("worm_mode %q resolved to %q; an unrecognised value must refuse", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("worm_mode %q: unexpected error %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("worm_mode %q resolved to %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// ValidateForBackup runs ResolveWORMMode, so an opted-out config must pass it.
// Otherwise the escape hatch exists in the provider and is unreachable from the
// command that needs it.
func TestABackupConfigMayOptOutOfObjectLock(t *testing.T) {
	cfg := &CLIConfig{
		DatabaseURL: "postgres://u:p@h:5432/d",
		Encryption:  EncryptionConfig{PublicKey: "age1testrecipient"},
		Storage: StorageConfig{
			Type: StorageTypeS3, Bucket: "b", WORMMode: WORMModeNone, RetentionDays: 30,
		},
	}
	if err := cfg.ValidateForBackup(); err != nil {
		t.Fatalf("a config that explicitly opts out of Object Lock must still validate: %v", err)
	}
}
