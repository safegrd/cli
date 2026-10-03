package cli

import (
	"os"
)

// ansi wraps s in an SGR colour code when stdout is a terminal and NO_COLOR
// is unset (https://no-color.org). Piped into a file or a CI log, escape codes
// are noise around the one value someone is trying to copy.
func ansi(code, s string) string {
	if !colorEnabled() {
		return s
	}
	return "\033[" + code + "m" + s + "\033[0m"
}

func colorEnabled() bool {
	if _, set := os.LookupEnv("NO_COLOR"); set {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
