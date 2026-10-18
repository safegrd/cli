package watch

import (
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const plainDump = `--
-- PostgreSQL database dump
--

-- Dumped from database version 16.4
CREATE EXTENSION IF NOT EXISTS pg_cron WITH SCHEMA pg_catalog;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;
COPY cron.job (jobid, schedule, command) FROM stdin;
1	0 3 * * *	SELECT 1
\.
COPY public.users (id, email) FROM stdin;
1	a@example.com
2	b@example.com
\.
COPY "Sales"."Order Items" (id) FROM stdin;
\.
INSERT INTO public.notes VALUES (1, 'x');
`

func writeDump(t *testing.T, body string, gz bool) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "backup.sql")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if gz {
		w := gzip.NewWriter(f)
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if _, err := f.WriteString(body); err != nil {
		t.Fatal(err)
	}
	return p
}

// A plain dump, gzipped or not: each table's rows, pg_cron's jobs set
// aside, the extensions and the server it came from.
func TestAPlainDumpIsCountedTableByTable(t *testing.T) {
	for _, gz := range []bool{false, true} {
		c, err := Inspect(context.Background(), writeDump(t, plainDump, gz))
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]int64{}
		for _, tb := range c.Tables {
			got[tb.Schema+"."+tb.TableName] = tb.RowCount
		}
		if c.Format != FormatPlain || c.Gzipped != gz || c.Rows != 3 || got["public.users"] != 2 || got["public.notes"] != 1 ||
			len(c.Tables) != 3 || c.CronJobs != 1 || c.ServerVersion != "16.4" || strings.Join(c.Extensions, ",") != "pg_cron,uuid-ossp" {
			t.Errorf("gzip %v: %+v, tables %v", gz, c, got)
		}
		if !c.Loadable() {
			t.Errorf("gzip %v: a plain single-database dump is loadable", gz)
		}
	}
}

func TestADumpCutShortIsRefused(t *testing.T) {
	cut := plainDump[:strings.Index(plainDump, "2\tb@example.com")]
	if _, err := Inspect(context.Background(), writeDump(t, cut, true)); err == nil || !strings.Contains(err.Error(), "cut short") {
		t.Errorf("a dump that ends inside a table's rows: %v", err)
	}
	if _, err := Inspect(context.Background(), writeDump(t, "hello\n", false)); err == nil || !strings.Contains(err.Error(), "not a PostgreSQL dump") {
		t.Errorf("a file that is not a dump: %v", err)
	}
}

func TestAClusterDumpIsReadAndNotLoaded(t *testing.T) {
	body := "--\n-- PostgreSQL database cluster dump\n--\nCREATE ROLE app;\n\\connect shop\nCOPY public.users (id) FROM stdin;\n1\n\\.\n"
	c, err := Inspect(context.Background(), writeDump(t, body, false))
	if err != nil {
		t.Fatal(err)
	}
	if c.Format != FormatCluster || c.Loadable() || len(c.Tables) != 1 || c.Tables[0].Schema != "shop:public" {
		t.Errorf("a cluster dump: %+v", c)
	}
}

// What a load sends psql: no pg_cron job rows, no extension comments, and no
// setting the sandbox's server lacks (pg_dump 18's transaction_timeout on a
// PostgreSQL 16 sandbox), everything else as it was.
func TestTheLoadFilterLeavesOutJobsCommentsAndUnknownSettings(t *testing.T) {
	in := "SET statement_timeout = 0;\nSET transaction_timeout = 0;\nSELECT pg_catalog.set_config('search_path', '', false);\n" +
		"COMMENT ON EXTENSION pg_cron IS 'x';\nCOPY cron.job (jobid) FROM stdin;\n1\n\\.\nCOPY public.users (id) FROM stdin;\n1\n\\.\n"
	var out strings.Builder
	if err := filterSQL(strings.NewReader(in), &out, map[string]bool{"statement_timeout": true, "search_path": true}); err != nil {
		t.Fatal(err)
	}
	want := "SET statement_timeout = 0;\nSELECT pg_catalog.set_config('search_path', '', false);\nCOPY public.users (id) FROM stdin;\n1\n\\.\n"
	if out.String() != want {
		t.Errorf("filtered:\n%s\nwant:\n%s", out.String(), want)
	}
}
