//go:build !linux && !darwin

package runner

import (
	"errors"
	"os/exec"
)

type runAs struct{}

func sandboxCredential(string) (*runAs, error) {
	return nil, errors.New("a local sandbox runs on Linux and macOS only; point drill.sandbox_url at a database")
}

func (r *runAs) own(string) error { return nil }
func (r *runAs) apply(*exec.Cmd)  {}
