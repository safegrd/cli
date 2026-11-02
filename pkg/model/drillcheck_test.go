package model

import (
	"strings"
	"testing"
)

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
	for name, c := range map[string]struct {
		checks []DrillCheck
		says   string
	}{
		"no name":          {[]DrillCheck{{SQL: "SELECT 1", Expect: "1"}}, "drill check 1 has no name"},
		"named twice":      {[]DrillCheck{ok, ok}, `"n" is named twice`},
		"both":             {[]DrillCheck{{Name: "n", SQL: "SELECT 1", Expect: "1", Command: "true"}}, "has both sql and command"},
		"neither":          {[]DrillCheck{{Name: "n"}}, "has neither sql nor command"},
		"sql, no expect":   {[]DrillCheck{{Name: "n", SQL: "SELECT 1"}}, "has no expect"},
		"command, expect":  {[]DrillCheck{{Name: "n", Command: "true", Expect: "0"}}, "leave out expect"},
		"order on text":    {[]DrillCheck{{Name: "n", SQL: "SELECT 1", Expect: "> abc"}}, "its value must be a number"},
		"operator only":    {[]DrillCheck{{Name: "n", SQL: "SELECT 1", Expect: ">="}}, "has an operator and no value"},
		"unknown variable": {[]DrillCheck{{Name: "n", SQL: "SELECT '${SAFEGRD_SNAPSHOT_TIME}'", Expect: "1"}}, "names ${SAFEGRD_SNAPSHOT_TIME}"},
		"unclosed":         {[]DrillCheck{{Name: "n", SQL: "SELECT '${SAFEGRD_SNAPSHOT_CREATED_AT'", Expect: "1"}}, "names ${SAFEGRD_SNAPSHOT_CREATED_AT'"},
	} {
		if err := ValidateDrillChecks(c.checks); err == nil || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: %v; want an error saying %q", name, err, c.says)
		}
	}
	fresh := DrillCheck{Name: "fresh", Expect: "true",
		SQL: "SELECT max(created_at) >= timestamptz '${SAFEGRD_SNAPSHOT_CREATED_AT}' - interval '1 hour' FROM orders"}
	if err := ValidateDrillChecks([]DrillCheck{ok, fresh, {Name: "smoke", Command: "./smoke.sh"}}); err != nil {
		t.Errorf("valid checks refused: %v", err)
	}
}
