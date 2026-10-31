package cli

import "testing"

// The statement that writes matching rows into the target: every column
// the target has and does not compute, matched on the primary key, left
// alone or replaced, and each row says whether it was new.
func TestRowsUpsertSQLMatchesOnThePrimaryKey(t *testing.T) {
	got := rowsUpsertSQL(`"Sales"."Order Items"`, `"safegrd_rows_0"`, []string{"Line No", "qty", "note"}, []string{"Line No"}, "qty > 2", false)
	want := `INSERT INTO "Sales"."Order Items" ("Line No", "qty", "note") SELECT "Line No", "qty", "note" FROM "safegrd_rows_0" WHERE (qty > 2)` +
		` ON CONFLICT ("Line No") DO NOTHING RETURNING (xmax = 0) AS inserted`
	if got != want {
		t.Errorf("kept:\n got %s\nwant %s", got, want)
	}
	got = rowsUpsertSQL(`public.orders`, `"safegrd_rows_1"`, []string{"a", "b", "c"}, []string{"a", "b"}, "c IS NULL", true)
	want = `INSERT INTO public.orders ("a", "b", "c") SELECT "a", "b", "c" FROM "safegrd_rows_1" WHERE (c IS NULL)` +
		` ON CONFLICT ("a", "b") DO UPDATE SET "a" = EXCLUDED."a", "b" = EXCLUDED."b", "c" = EXCLUDED."c" RETURNING (xmax = 0) AS inserted`
	if got != want {
		t.Errorf("overwrite:\n got %s\nwant %s", got, want)
	}
}
