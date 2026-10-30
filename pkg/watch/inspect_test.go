package watch

import (
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safegrd/cli/pkg/model"
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

// A mysqldump file as Coolify writes one (mysqldump -u root -p... DATABASE,
// no --databases): the header names the database and the server, each
// table's rows are counted from its INSERT statements, and the completion
// line is the end.
const mysqlDump = "-- MariaDB dump 10.19  Distrib 10.11.6-MariaDB, for Linux (x86_64)\n--\n-- Host: localhost    Database: shop\n" +
	"-- ------------------------------------------------------\n-- Server version\t8.4.11\n\n" +
	"DROP TABLE IF EXISTS `users`;\nCREATE TABLE `users` (\n  `id` int NOT NULL\n);\n" +
	"INSERT INTO `users` VALUES (1,'a@example.com'),(2,'b,(c)@example.com');\n" +
	"CREATE TABLE `orders` (\n  `id` int NOT NULL\n);\n" +
	"INSERT INTO `orders` VALUES (1),(2),(3);\nCREATE TABLE `empty` (\n  `id` int\n);\n" +
	"-- Dump completed on 2026-10-30 10:00:00\n"

func TestAMySQLDumpIsCountedTableByTable(t *testing.T) {
	for _, gz := range []bool{false, true} {
		c, err := Inspect(context.Background(), writeDump(t, mysqlDump, gz))
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]int64{}
		for _, tb := range c.Tables {
			got[tb.Schema+"."+tb.TableName] = tb.RowCount
		}
		if c.Engine != "mysql" || c.Format != FormatMySQL || c.Gzipped != gz || c.Database != "shop" || c.ServerVersion != "8.4.11" ||
			c.Rows != 5 || len(c.Tables) != 3 || got["shop.users"] != 2 || got["shop.orders"] != 3 || got["shop.empty"] != 0 || !c.Loadable() {
			t.Errorf("gzip %v: %+v, tables %v", gz, c, got)
		}
	}
	cut := mysqlDump[:strings.Index(mysqlDump, "-- Dump completed")]
	if _, err := Inspect(context.Background(), writeDump(t, cut, false)); err == nil || !strings.Contains(err.Error(), "cut short") {
		t.Errorf("a dump without its completion line: %v", err)
	}
	// mysqldump --all-databases creates and switches databases: read, and
	// not loaded, with each table named by its database.
	all := "-- MySQL dump 10.13  Distrib 8.4.11, for Linux (aarch64)\n--\n-- Host: localhost    Database: \n-- Server version\t8.4.11\n" +
		"CREATE DATABASE /*!32312 IF NOT EXISTS*/ `shop` /*!40100 DEFAULT CHARACTER SET utf8mb4 */;\n\nUSE `shop`;\n" +
		"CREATE TABLE `users` (\n  `id` int\n);\nINSERT INTO `users` VALUES (1);\n" +
		"CREATE DATABASE /*!32312 IF NOT EXISTS*/ `crm` /*!40100 DEFAULT CHARACTER SET utf8mb4 */;\n\nUSE `crm`;\n" +
		"CREATE TABLE `users` (\n  `id` int\n);\nINSERT INTO `users` VALUES (1),(2);\n-- Dump completed\n"
	c, err := Inspect(context.Background(), writeDump(t, all, true))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, tb := range c.Tables {
		got[tb.Schema+"."+tb.TableName] = tb.RowCount
	}
	if c.Loadable() || !c.CreatesDatabase || c.Rows != 3 || got["shop.users"] != 1 || got["crm.users"] != 2 {
		t.Errorf("an --all-databases dump: %+v, tables %v", c, got)
	}
}

// A mongodump archive, as Coolify writes one with --gzip --archive: each
// collection's documents, the server, and the one database it holds. One
// cut short is refused.
func TestAMongoArchiveIsCountedCollectionByCollection(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "dump", "testdata", "mongo-shop.archive"))
	if err != nil {
		t.Fatal(err)
	}
	for _, gz := range []bool{false, true} {
		c, err := Inspect(context.Background(), writeDump(t, string(raw), gz))
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]int64{}
		for _, tb := range c.Tables {
			got[tb.Schema+"."+tb.TableName] = tb.RowCount
		}
		if c.Engine != "mongodb" || c.Format != FormatMongoArchive || c.Gzipped != gz || c.Database != "shop" || c.ServerVersion != "7.0.43" ||
			c.Rows != 4 || len(c.Tables) != 3 || got["shop.orders"] != 3 || got["shop.customers"] != 1 || got["shop.empty"] != 0 || !c.Loadable() {
			t.Errorf("gzip %v: %+v, tables %v", gz, c, got)
		}
		if a, b := c.CountWords(); a != "collections" || b != "documents" {
			t.Errorf("counted in %s and %s", a, b)
		}
	}
	if _, err := Inspect(context.Background(), writeDump(t, string(raw[:len(raw)*2/3]), true)); err == nil || !strings.Contains(err.Error(), "cut short") && !strings.Contains(err.Error(), "read to its end") {
		t.Errorf("an archive cut short: %v", err)
	}
}

// Coolify writes every database's backups under one tree, each named by
// its engine: a location reads only the files of its surface's engine, and
// names Coolify as the tool for each.
func TestALocationReadsOnlyItsEnginesBackups(t *testing.T) {
	for _, tc := range []struct {
		engine string
		name   string
		want   bool
	}{
		{"", "pg-dump-app-1760000000-6f1c2a.dmp", true}, {"", "mysql-dump-app-1760000000-6f1c2a.dmp", false},
		{"", "app-2026-10-18.sql.gz", true}, {"", "clickhouse-backup-x.tar", false},
		{"mysql", "mysql-dump-app-1.dmp", true}, {"mysql", "mariadb-dump-app-1.dmp", true}, {"mysql", "pg-dump-app-1.dmp", false},
		{"mongodb", "mongo-dump-app-1.tar.gz", true}, {"mongodb", "mysql-dump-app-1.dmp", false}, {"mongodb", "x.part", false},
	} {
		if got := (Location{Engine: model.SurfaceType(tc.engine)}).isDump(tc.name); got != tc.want {
			t.Errorf("engine %q, %s: %v, want %v", tc.engine, tc.name, got, tc.want)
		}
	}
	for _, name := range []string{"pg-dump-a.dmp", "mysql-dump-a.dmp", "mariadb-dump-a.dmp", "mongo-dump-a.tar.gz"} {
		if Tool(Object{Key: "data/" + name}) != "Coolify" {
			t.Errorf("%s was not made by Coolify", name)
		}
	}
	if Tool(Object{Key: "app.sql.gz"}) != "" {
		t.Error("a cron dump has no tool")
	}
	if SandboxEngine("mysql://a@b/c") != "mysql" || SandboxEngine("mongodb://a@b/c") != "mongodb" || SandboxEngine("postgres://a@b/c") != "postgres" {
		t.Error("the sandbox's engine")
	}
}
