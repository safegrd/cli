package cli

import "testing"

// --table takes a name as written or as psql quotes it.
func TestSplitTableName(t *testing.T) {
	for _, c := range []struct{ in, schema, table string }{
		{"orders", "public", "orders"},
		{"billing.events", "billing", "events"},
		{"public.weird.name", "public", "weird.name"},
		{`"Sales Team"."Order Items"`, "Sales Team", "Order Items"},
		{`"Sales Team".orders`, "Sales Team", "orders"},
		{`"say ""hi"""`, "public", `say "hi"`},
		{`"a.b"."c.d"`, "a.b", "c.d"},
	} {
		s, tb, ok := splitTableName(c.in)
		if !ok || s != c.schema || tb != c.table {
			t.Errorf("splitTableName(%q) = %q, %q, %v; want %q, %q", c.in, s, tb, ok, c.schema, c.table)
		}
	}
	for _, bad := range []string{`"unclosed`, `"a"x.b`, `"a"."b"."c"`} {
		if _, _, ok := splitTableName(bad); ok {
			t.Errorf("splitTableName(%q) accepted a malformed name", bad)
		}
	}
}
