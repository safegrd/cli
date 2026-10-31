package cli

import (
	"strings"
	"testing"

	"github.com/safegrd/cli/pkg/model"
)

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

func TestATableOfAnotherEngineIsNamedAloneOrWithItsDatabase(t *testing.T) {
	manifest := &model.SnapshotMetadata{TableStats: []model.TableStat{
		{Schema: "shop", TableName: "orders"}, {Schema: "shop", TableName: "users.archive"},
	}}
	for _, c := range []struct {
		name  string
		want  string
		words string
	}{
		{"orders", "orders", ""},
		{"shop.orders", "orders", ""},
		{"users.archive", "users.archive", ""},
		{"shop.users.archive", "users.archive", ""},
		{"other.orders", "", "names database other"},
		{"rich", "", "holds no collection rich"},
	} {
		picks, err := engineTablePicks(model.SurfaceTypeMongoDB, manifest, "snap-1", []string{c.name})
		switch {
		case c.words != "":
			if err == nil || !strings.Contains(err.Error(), c.words) {
				t.Errorf("%s: %v, want %q", c.name, err, c.words)
			}
		case err != nil || len(picks) != 1 || picks[0].TableName != c.want:
			t.Errorf("%s: %+v %v, want %s", c.name, picks, err, c.want)
		}
	}
	if _, err := engineTablePicks(model.SurfaceTypeMySQL, manifest, "snap-1", []string{"orders", "shop.orders"}); err == nil || !strings.Contains(err.Error(), "given twice") {
		t.Errorf("the same table twice: %v", err)
	}
}

func TestATableIsLookedForUnderEveryEnginesName(t *testing.T) {
	got, err := tablePaths("orders")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"data/public/orders.copy", "mysql/tables/orders.sql", "mongo/collections/orders.bson", "sqlite/database.sqlite"}; strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("tablePaths(orders) = %v, want %v", got, want)
	}
	got, _ = tablePaths("shop.users.archive")
	if want := "data/shop/users.archive.copy mysql/tables/users.archive.sql mongo/collections/users.archive.bson mongo/collections/shop.users.archive.bson sqlite/database.sqlite"; strings.Join(got, " ") != want {
		t.Errorf("tablePaths(shop.users.archive) = %v", got)
	}
}
