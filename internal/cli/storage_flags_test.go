package cli

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Every command that points at an S3 bucket names it the same way. backup
// used to take --bucket while verify and init took --s3-bucket, so a command
// copied from one to the other failed with "unknown flag".
func TestS3FlagsAreNamedTheSameOnEveryCommand(t *testing.T) {
	bare := map[string]string{
		"bucket": "s3-bucket", "prefix": "s3-prefix", "region": "s3-region",
		"endpoint": "s3-endpoint", "access-key": "s3-access-key", "secret-key": "s3-secret-key",
	}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		c.LocalFlags().VisitAll(func(f *pflag.Flag) {
			if want, ok := bare[f.Name]; ok {
				t.Errorf("%s defines --%s; name it --%s like every other command", c.CommandPath(), f.Name, want)
			}
		})
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(RootCmd)

	// The commands that take a bucket take the whole set.
	for _, path := range [][]string{{"backup"}, {"verify"}} {
		c, _, err := RootCmd.Find(path)
		if err != nil {
			t.Fatalf("%v: %v", path, err)
		}
		for _, name := range []string{"s3-bucket", "s3-prefix", "s3-region", "s3-endpoint", "s3-access-key", "s3-secret-key"} {
			if c.Flags().Lookup(name) == nil {
				t.Errorf("%s has no --%s", c.CommandPath(), name)
			}
		}
	}
	initCmd, _, err := RootCmd.Find([]string{"init"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"s3-bucket", "s3-prefix", "s3-region", "s3-endpoint"} {
		if initCmd.Flags().Lookup(name) == nil {
			t.Errorf("init has no --%s", name)
		}
	}
}
