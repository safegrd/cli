package dump

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// A per-table MySQL dump is the dump cut at each object's comment block:
// what comes before the first object is the head, each table (its
// structure, rows and triggers) is its own entry, and routines, the final
// view definitions and the closing settings are the tail. Concatenated in
// archive order the entries are the dump, byte for byte.
func TestAMySQLRunIsTheDumpCutPerTable(t *testing.T) {
	dump := strings.Join([]string{
		"-- MariaDB dump 10.19  Distrib 10.10.2-MariaDB, for osx10.17 (x86_64)",
		"--",
		"-- Host: 127.0.0.1    Database: shop",
		"-- ------------------------------------------------------",
		"-- Server version\t8.4.3",
		"",
		"/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;",
		"/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;",
		"/*!40103 SET TIME_ZONE='+00:00' */;",
		"",
		"--",
		"-- Table structure for table `audit`",
		"--",
		"",
		"DROP TABLE IF EXISTS `audit`;",
		"CREATE TABLE `audit` (",
		"  `id` int NOT NULL AUTO_INCREMENT",
		") ENGINE=InnoDB;",
		"",
		"--",
		"-- Dumping data for table `audit`",
		"--",
		"",
		"LOCK TABLES `audit` WRITE;",
		"INSERT INTO `audit` VALUES (1),(2);",
		"UNLOCK TABLES;",
		"",
		"--",
		"-- Table structure for table `order``s`",
		"--",
		"",
		"CREATE TABLE `order``s` (",
		"  `id` int NOT NULL",
		") ENGINE=InnoDB;",
		"INSERT INTO `order``s` VALUES (1);",
		"/*!50003 CREATE*/ /*!50017 DEFINER=`app`@`%`*/ /*!50003 TRIGGER orders_audit AFTER INSERT ON `order``s` FOR EACH ROW INSERT INTO audit VALUES (NULL) */;;",
		"",
		"--",
		"-- Temporary view structure for view `paid`",
		"--",
		"",
		"/*!50001 CREATE VIEW `paid` AS SELECT 1 AS `id` */;",
		"",
		"--",
		"-- Dumping routines for database 'shop'",
		"--",
		"/*!50003 CREATE*/ /*!50020 DEFINER=`app`@`%`*/ /*!50003 PROCEDURE `refill`() BEGIN INSERT INTO audit (what) VALUES ('x'); END */;;",
		"",
		"--",
		"-- Final view structure for view `paid`",
		"--",
		"",
		"/*!50001 CREATE ALGORITHM=UNDEFINED VIEW `paid` AS select `id` from `order``s` */;",
		"/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;",
		"",
		"/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;",
		"",
		"-- Dump completed on 2026-10-13 10:00:00",
		"",
	}, "\n")
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	w := newMySQLSectionWriter(tw)
	// Fed in odd pieces, so a boundary that falls inside a line is tested.
	for i := 0; i < len(dump); i += 7 {
		end := i + 7
		if end > len(dump) {
			end = len(dump)
		}
		if _, err := w.Write([]byte(dump[i:end])); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(w.Tables, ","), "audit,order`s,paid"; got != want {
		t.Errorf("sections %q, want %q", got, want)
	}
	var names []string
	var joined bytes.Buffer
	tr := tar.NewReader(&buf)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, hdr.Name)
		if _, err := io.Copy(&joined, tr); err != nil {
			t.Fatal(err)
		}
	}
	if got, want := strings.Join(names, " "), "mysql/head.sql mysql/tables/audit.sql mysql/tables/order`s.sql mysql/tables/paid.sql mysql/tail.sql"; got != want {
		t.Errorf("entries %q, want %q", got, want)
	}
	if joined.String() != dump {
		t.Errorf("the sections do not concatenate to the dump:\n%s", joined.String())
	}
	if MySQLRunTable("mysql/tables/order`s.sql.3") != "order`s" || MySQLRunTable("mysql/tail.sql") != "" {
		t.Error("MySQLRunTable does not name the table of an entry")
	}
}

// A dump with no object (an empty database) is one head entry, and one
// whose last object is a table with nothing after it but the closing
// settings has a tail from those settings.
func TestAMySQLRunWithNoTablesIsOneHead(t *testing.T) {
	dump := "-- MySQL dump\n--\n-- Host: x\n\n/*!40103 SET TIME_ZONE='+00:00' */;\n/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;\n\n-- Dump completed on 2026-10-13 10:00:00\n"
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	w := newMySQLSectionWriter(tw)
	if _, err := w.Write([]byte(dump)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	tr := tar.NewReader(&buf)
	hdr, err := tr.Next()
	if err != nil || hdr.Name != "mysql/head.sql" {
		t.Fatalf("first entry %v %v", hdr, err)
	}
	body, _ := io.ReadAll(tr)
	if string(body) != dump {
		t.Errorf("head is not the dump:\n%s", body)
	}
	if _, err := tr.Next(); err != io.EOF {
		t.Errorf("more than one entry: %v", err)
	}
}

// Chunked entry names: part 0 is the base name, later parts carry ".N";
// a name that is not one of the dump's streams is neither.
func TestChunkedEntryNames(t *testing.T) {
	for _, c := range []struct {
		name string
		base string
		part int
		ok   bool
	}{
		{"data/public/t.copy", "data/public/t.copy", 0, true},
		{"data/public/t.copy.3", "data/public/t.copy", 3, true},
		{"data/public/t.copy.2.copy", "data/public/t.copy.2.copy", 0, true},
		{"mysql/tables/a.1.sql", "mysql/tables/a.1.sql", 0, true},
		{"mysql/tables/a.sql.12", "mysql/tables/a.sql", 12, true},
		{"mongo/collections/c.bson.1", "mongo/collections/c.bson", 1, true},
		{"mongo/dump.archive.2", "mongo/dump.archive", 2, true},
		{"manifest.json", "", 0, false},
		{"left-out.json", "", 0, false},
		{"files/x.txt.1", "", 0, false},
	} {
		base, part, ok := parseChunkedEntry(c.name)
		if base != c.base || part != c.part || ok != c.ok {
			t.Errorf("%s: %q %d %v, want %q %d %v", c.name, base, part, ok, c.base, c.part, c.ok)
		}
	}
	for _, name := range []string{"plain", "with/slash", "back\\slash", ".hidden", "..", "100%", "tab\there", "ünïcode"} {
		esc := runEntryName(name)
		if strings.ContainsAny(esc, "/\\") || strings.HasPrefix(esc, ".") {
			t.Errorf("%q escapes to %q, which is not one path element", name, esc)
		}
		if got := unescapeRunEntryName(esc); got != name {
			t.Errorf("%q escapes to %q and back to %q", name, esc, got)
		}
	}
}

// A per-collection MongoDB run holds the prelude and one file of documents
// per collection, without the archive's block framing; rebuilt, it is an
// archive mongorestore's reader parses to the same collections, counts and
// CRCs, and of exactly the size computed for it.
func TestAMongoRunRebuildsTheArchive(t *testing.T) {
	src, err := os.ReadFile("testdata/mongo-shop.archive")
	if err != nil {
		t.Fatal(err)
	}
	want, err := readMongoArchive(bytes.NewReader(src), nil)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	rw := newMongoRunWriter(tw)
	if _, err := readMongoArchive(bytes.NewReader(src), rw); err != nil {
		t.Fatal(err)
	}
	if err := rw.Close(); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	entries := map[string][]byte{}
	var names []string
	tr := tar.NewReader(&buf)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		entries[hdr.Name] = b
		names = append(names, hdr.Name)
	}
	if got, want := strings.Join(names, " "), "mongo/prelude.bson mongo/collections/customers.bson mongo/collections/orders.bson mongo/collections/empty.bson"; got != want {
		t.Errorf("entries %q, want %q", got, want)
	}
	if len(entries["mongo/collections/empty.bson"]) != 0 {
		t.Error("the empty collection's file is not empty")
	}
	if _, ok := entries["mongo/collections/v.bson"]; ok {
		t.Error("the view got a file")
	}
	var parts []MongoRunPart
	for _, name := range names {
		if name == MongoPreludeEntry {
			continue
		}
		b := entries[name]
		parts = append(parts, MongoRunPart{Collection: MongoRunCollection(name), Size: int64(len(b)), Open: func(w io.Writer) error { _, err := w.Write(b); return err }})
	}
	size, err := MongoRunArchiveSize(entries[MongoPreludeEntry], parts)
	if err != nil {
		t.Fatal(err)
	}
	var rebuilt bytes.Buffer
	if err := WriteMongoRunArchive(entries[MongoPreludeEntry], parts, &rebuilt); err != nil {
		t.Fatal(err)
	}
	if int64(rebuilt.Len()) != size {
		t.Errorf("the rebuilt archive is %d bytes, the size computed for it %d", rebuilt.Len(), size)
	}
	got, err := readMongoArchive(bytes.NewReader(rebuilt.Bytes()), nil)
	if err != nil {
		t.Fatalf("the rebuilt archive does not parse: %v", err)
	}
	if len(got.CRCFailed) > 0 {
		t.Errorf("CRCs fail on %v", got.CRCFailed)
	}
	if missing := got.missingEnds(); len(missing) > 0 {
		t.Errorf("namespaces never ended: %v", missing)
	}
	if strings.Join(got.Collections, ",") != strings.Join(want.Collections, ",") || strings.Join(got.Views, ",") != strings.Join(want.Views, ",") {
		t.Errorf("collections %v views %v, want %v %v", got.Collections, got.Views, want.Collections, want.Views)
	}
	for ns, n := range want.Docs {
		if got.Docs[ns] != n || got.DocBytes[ns] != want.DocBytes[ns] {
			t.Errorf("%s: %d documents of %d bytes, want %d of %d", ns, got.Docs[ns], got.DocBytes[ns], n, want.DocBytes[ns])
		}
	}
	if got.ServerVersion != want.ServerVersion {
		t.Errorf("server version %q, want %q", got.ServerVersion, want.ServerVersion)
	}
}
