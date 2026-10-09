package model

import "testing"

func TestADrillExpectationComparesNumbersAsNumbersAndTextAsText(t *testing.T) {
	cases := []struct {
		expect, actual string
		holds          bool
	}{
		{"0", "0", true},
		{"0", "1", false},
		{"> 0", "3", true},
		{">0", "0", false},
		{">= 1000", "1000", true},
		{"< 10", "9.5", true},
		{"<= 2", "2.0", true},
		{"!= 0", "0", false},
		{"42.75", "42.75", true},
		{"42.75", "4275e-2", true},
		{"true", "t", true},
		{"true", "false", false},
		{"ok", "ok", true},
		{"!= broken", "ok", true},
		{"> 5", "NULL", false},
		{"0", "NULL", false},
	}
	for _, c := range cases {
		e, err := ParseDrillExpect(c.expect)
		if err != nil {
			t.Fatalf("expect %q: %v", c.expect, err)
		}
		if got := e.Holds(c.actual); got != c.holds {
			t.Errorf("expect %q against %q: holds = %v, want %v", c.expect, c.actual, got, c.holds)
		}
	}
}

func TestDrillChecksThatCannotRunAreRefused(t *testing.T) {
	ok := DrillCheck{Name: "n", SQL: "SELECT 1", Expect: "1"}
	for name, checks := range map[string][]DrillCheck{
		"no name":         {{SQL: "SELECT 1", Expect: "1"}},
		"named twice":     {ok, ok},
		"both":            {{Name: "n", SQL: "SELECT 1", Expect: "1", Command: "true"}},
		"neither":         {{Name: "n"}},
		"sql, no expect":  {{Name: "n", SQL: "SELECT 1"}},
		"command, expect": {{Name: "n", Command: "true", Expect: "0"}},
		"order on text":   {{Name: "n", SQL: "SELECT 1", Expect: "> abc"}},
		"operator only":   {{Name: "n", SQL: "SELECT 1", Expect: ">="}},
	} {
		if err := ValidateDrillChecks(checks); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := ValidateDrillChecks([]DrillCheck{ok, {Name: "smoke", Command: "./smoke.sh"}}); err != nil {
		t.Errorf("valid checks refused: %v", err)
	}
}
