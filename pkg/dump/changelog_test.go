package dump

import "testing"

func TestLSNOrder(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"0/16B3748", "0/16B3748", true},
		{"0/16B3749", "0/16B3748", true},
		{"1/0", "0/FFFFFFFF", true},
		{"0/FFFFFFFF", "1/0", false},
		{"", "0/1", false},
		{"0/1", "", false},
		{"bogus", "0/1", false},
	} {
		if got := lsnAtOrAfter(c.a, c.b); got != c.want {
			t.Errorf("lsnAtOrAfter(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
