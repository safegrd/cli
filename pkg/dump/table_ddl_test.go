package dump

import (
	"strings"
	"testing"
)

// One table's objects come out of a schema-only dump: the table, its owned
// sequence and default, its constraints and indexes, and nothing of the table
// whose name starts the same or of any other.
func TestTableDefinitionPicksOneTablesObjects(t *testing.T) {
	entry := func(name, typ, schema, body string) string {
		return "--\n-- Name: " + name + "; Type: " + typ + "; Schema: " + schema + "; Owner: -\n--\n\n" + body + "\n\n"
	}
	pre := "SET search_path = '';\n\n" +
		entry("order", "TABLE", "public", `CREATE TABLE public."order" (id bigint NOT NULL);`) +
		entry("order_id_seq", "SEQUENCE", "public", `CREATE SEQUENCE public.order_id_seq;`) +
		entry("order_id_seq", "SEQUENCE OWNED BY", "public", `ALTER SEQUENCE public.order_id_seq OWNED BY public."order".id;`) +
		entry("order_items", "TABLE", "public", `CREATE TABLE public.order_items (id int);`) +
		entry("order id", "DEFAULT", "public", `ALTER TABLE ONLY public."order" ALTER COLUMN id SET DEFAULT nextval('public.order_id_seq'::regclass);`) +
		entry("order", "TABLE", "audit", `CREATE TABLE audit."order" (id int);`)
	post := entry("order order_pkey", "CONSTRAINT", "public", `ALTER TABLE ONLY public."order" ADD CONSTRAINT order_pkey PRIMARY KEY (id);`) +
		entry("order_items_pkey", "CONSTRAINT", "public", `ALTER TABLE ONLY public.order_items ADD CONSTRAINT order_items_pkey PRIMARY KEY (id);`) +
		entry("order_by_day", "INDEX", "public", `CREATE INDEX order_by_day ON public."order" USING btree (id);`) +
		entry("order_items_by_id", "INDEX", "public", `CREATE INDEX order_items_by_id ON public.order_items USING btree (id);`)
	seqs := "-- Sequence positions\nSELECT pg_catalog.setval('\"public\".\"order_id_seq\"', 42, true);\nSELECT pg_catalog.setval('\"public\".\"order_items_id_seq\"', 7, true);\n"

	ddl, ok := TableDefinition(pre, post, seqs, "public", "order", []string{"public.order_id_seq"})
	if !ok {
		t.Fatal("no TABLE entry found for public.order")
	}
	for _, want := range []string{`CREATE TABLE public."order"`, "CREATE SEQUENCE public.order_id_seq", "OWNED BY", "SET DEFAULT nextval", "order_pkey", "CREATE INDEX order_by_day"} {
		if !strings.Contains(ddl.Create, want) {
			t.Errorf("missing %q:\n%s", want, ddl.Create)
		}
	}
	for _, not := range []string{"order_items", `audit."order"`, "SET search_path"} {
		if strings.Contains(ddl.Create, not) {
			t.Errorf("took %q, which is not public.order's:\n%s", not, ddl.Create)
		}
	}
	if ddl.Objects != 6 || ddl.Setvals != "SELECT pg_catalog.setval('\"public\".\"order_id_seq\"', 42, true);\n" {
		t.Errorf("objects %d, setvals %q", ddl.Objects, ddl.Setvals)
	}
	if _, ok := TableDefinition(pre, post, seqs, "public", "gone", nil); ok {
		t.Error("a table the dump does not hold was found")
	}
}
