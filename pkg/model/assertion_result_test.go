package model

import (
	"encoding/json"
	"strings"
	"testing"
)

// A check that could not run reads as not_run, never as a failure, to a
// reader of the JSON that looks at one field; and the JSON still reads back.
func TestAnAssertionCarriesItsResultInTheJSON(t *testing.T) {
	for _, c := range []struct {
		a    AssertionResult
		want string
	}{
		{AssertionResult{Name: "TableCountMatch", Passed: true}, `"result":"passed"`},
		{AssertionResult{Name: "newest order is recent", Kind: AssertionKindCheck}, `"result":"failed"`},
		{AssertionResult{Name: "amcheck", Kind: AssertionKindData, NotRun: true}, `"result":"not_run"`},
	} {
		b, err := json.Marshal(c.a)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), c.want) || !strings.Contains(string(b), `"name":"`+c.a.Name+`"`) {
			t.Errorf("%s: %s, want %s", c.a.Name, b, c.want)
		}
		var back AssertionResult
		if err := json.Unmarshal(b, &back); err != nil || back != c.a {
			t.Errorf("%s: read back %+v (%v), want %+v", c.a.Name, back, err, c.a)
		}
	}
}
