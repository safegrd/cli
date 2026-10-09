package model

import (
	"fmt"
	"strconv"
	"strings"
)

// DrillCheck is one check of the customer's own that a Fire Drill runs
// against the sandbox once the snapshot is restored into it, beside the
// table, row and extension counts every drill makes. It is either a query
// whose first column of the first row is held to Expect, or a command that
// passes when it exits 0.
type DrillCheck struct {
	// Name is what the drill report and the console call the check.
	Name string `yaml:"name" json:"name"`
	// SQL is a single statement, run in a read-only transaction.
	SQL string `yaml:"sql,omitempty" json:"sql,omitempty"`
	// Expect is the value the query must return: "42", "true", "> 0",
	// ">= 1000", "!= 0". With an operator both sides must be numbers,
	// except "=" and "!=", which compare text when either side is not.
	Expect string `yaml:"expect,omitempty" json:"expect,omitempty"`
	// Command runs through sh -c with SAFEGRD_SANDBOX_URL set to the
	// sandbox's connection string.
	Command string `yaml:"command,omitempty" json:"command,omitempty"`
	// TimeoutSeconds bounds the check: 60 for a query and 300 for a
	// command when it is 0.
	TimeoutSeconds int `yaml:"timeout_seconds,omitempty" json:"timeout_seconds,omitempty"`
}

// ValidateDrillChecks refuses checks a drill could not run: no name, a name
// used twice, neither or both of sql and command, a query with no expected
// value, or an expected value that does not parse.
func ValidateDrillChecks(checks []DrillCheck) error {
	seen := map[string]bool{}
	for i, c := range checks {
		name := strings.TrimSpace(c.Name)
		if name == "" {
			return fmt.Errorf("drill check %d has no name", i+1)
		}
		if seen[name] {
			return fmt.Errorf("drill check %q is named twice", name)
		}
		seen[name] = true
		hasSQL, hasCmd := strings.TrimSpace(c.SQL) != "", strings.TrimSpace(c.Command) != ""
		switch {
		case hasSQL && hasCmd:
			return fmt.Errorf("drill check %q has both sql and command; give it one", name)
		case !hasSQL && !hasCmd:
			return fmt.Errorf("drill check %q has neither sql nor command", name)
		case hasSQL && strings.TrimSpace(c.Expect) == "":
			return fmt.Errorf("drill check %q has no expect: give the value the query must return, such as \"> 0\"", name)
		case hasCmd && strings.TrimSpace(c.Expect) != "":
			return fmt.Errorf("drill check %q is a command, which passes on exit 0; leave out expect", name)
		}
		if hasSQL {
			if _, err := ParseDrillExpect(c.Expect); err != nil {
				return fmt.Errorf("drill check %q: %w", name, err)
			}
		}
		if c.TimeoutSeconds < 0 {
			return fmt.Errorf("drill check %q has a negative timeout_seconds", name)
		}
	}
	return nil
}

// DrillExpect is a parsed DrillCheck.Expect.
type DrillExpect struct {
	Op    string // one of = != > >= < <=
	Value string
}

// ParseDrillExpect reads an expected value with an optional leading
// comparison. Ordering operators need a number.
func ParseDrillExpect(s string) (DrillExpect, error) {
	s = strings.TrimSpace(s)
	e := DrillExpect{Op: "="}
	for _, op := range []string{">=", "<=", "!=", ">", "<", "="} {
		if strings.HasPrefix(s, op) {
			e.Op, s = op, strings.TrimSpace(s[len(op):])
			break
		}
	}
	if s == "" {
		return e, fmt.Errorf("expect %q has an operator and no value", e.Op)
	}
	e.Value = s
	if e.Op != "=" && e.Op != "!=" {
		if _, err := strconv.ParseFloat(s, 64); err != nil {
			return e, fmt.Errorf("expect %q %s compares in order, so its value must be a number", e.Op, s)
		}
	}
	return e, nil
}

// String is the expectation as the report shows it.
func (e DrillExpect) String() string {
	if e.Op == "=" {
		return e.Value
	}
	return e.Op + " " + e.Value
}

// Holds reports whether actual, the query's value as text, meets the
// expectation. Numbers compare as numbers ("1.0" = "1"), and "t" and "f",
// which some drivers return for a boolean, compare equal to "true" and
// "false".
func (e DrillExpect) Holds(actual string) bool {
	a, aErr := strconv.ParseFloat(strings.TrimSpace(actual), 64)
	w, wErr := strconv.ParseFloat(e.Value, 64)
	if aErr == nil && wErr == nil {
		switch e.Op {
		case "=":
			return a == w
		case "!=":
			return a != w
		case ">":
			return a > w
		case ">=":
			return a >= w
		case "<":
			return a < w
		case "<=":
			return a <= w
		}
		return false
	}
	switch e.Op {
	case "=":
		return sameText(actual, e.Value)
	case "!=":
		return !sameText(actual, e.Value)
	}
	return false
}

func sameText(a, b string) bool {
	norm := func(s string) string {
		s = strings.TrimSpace(s)
		switch strings.ToLower(s) {
		case "t", "true":
			return "true"
		case "f", "false":
			return "false"
		}
		return s
	}
	return norm(a) == norm(b)
}
