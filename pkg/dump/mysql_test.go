package dump

import (
	"strings"
	"testing"
)

// The row counter must agree with the dump however its bytes arrive, and a
// value that looks like syntax must not count as a row.
func TestMySQLDumpCounterCountsTuplesNotSyntax(t *testing.T) {
	dump := strings.Join([]string{
		"-- MySQL dump 10.13",
		"/*!40101 SET NAMES utf8mb4 */;",
		"DROP TABLE IF EXISTS `orders`;",
		"CREATE TABLE `orders` (",
		"  `id` int NOT NULL,",
		"  `note` text",
		") ENGINE=InnoDB;",
		"CREATE TABLE `we``ird` (",
		"  `id` int",
		");",
		"CREATE TABLE `empty` (",
		"  `id` int",
		");",
		"LOCK TABLES `orders` WRITE;",
		`INSERT INTO ` + "`orders`" + ` VALUES (1,'a (fake) row'),(2,'it\'s (2)'),(3,'back\\slash)'),(4,NULL),(5,0xDEADBEEF);`,
		`INSERT INTO ` + "`orders`" + ` VALUES (6,'semi;colon'),(7,"dq (x)");`,
		"INSERT INTO `we``ird` (`id`) VALUES (1),(2);",
		"-- a comment with INSERT INTO `orders` VALUES (99);",
		"/*!50003 CREATE PROCEDURE `p`() BEGIN INSERT INTO `orders` VALUES (100); END */;;",
		"DELIMITER ;;",
		"CREATE DEFINER=`app`@`%` PROCEDURE `refill`()",
		"BEGIN",
		"INSERT INTO `orders` VALUES (101,'from a procedure'),(102,'x');",
		"END ;;",
		"DELIMITER ;",
		"-- Dump completed on 2026-09-24 10:00:00",
		"",
	}, "\n")
	for _, chunk := range []int{1, 7, len(dump)} {
		c := newMySQLDumpCounter()
		for i := 0; i < len(dump); i += chunk {
			end := min(i+chunk, len(dump))
			_, _ = c.Write([]byte(dump[i:end]))
		}
		if c.Rows["orders"] != 7 || c.Rows["we`ird"] != 2 || c.Rows["empty"] != 0 {
			t.Errorf("chunk %d: rows = %v", chunk, c.Rows)
		}
		if got := strings.Join(c.Tables(), ","); got != "orders,we`ird,empty" {
			t.Errorf("chunk %d: tables = %s", chunk, got)
		}
		if !c.Completed {
			t.Errorf("chunk %d: the completion line was not seen", chunk)
		}
	}
	c := newMySQLDumpCounter()
	_, _ = c.Write([]byte(strings.Replace(dump, "-- Dump completed", "-- Dump interrupted", 1)))
	if c.Completed {
		t.Error("a dump without its completion line counted as complete")
	}
}

func TestMySQLURLs(t *testing.T) {
	tg, err := parseMySQLURL("mysql://app:p%40ss@db.internal:3307/shop?tls=true")
	if err != nil || tg.User != "app" || tg.Password != "p@ss" || tg.Host != "db.internal" || tg.Port != 3307 || tg.Database != "shop" || tg.TLS != "true" {
		t.Fatalf("parsed %+v, %v", tg, err)
	}
	if _, err := parseMySQLURL("mysql://app@host/"); err == nil {
		t.Error("a URL with no database was accepted")
	}
	if !SameMySQLDatabase("mysql://a@localhost:3306/x", "mysql://b:pw@127.0.0.1/x") || SameMySQLDatabase("mysql://a@h/x", "mysql://a@h/y") {
		t.Error("SameMySQLDatabase")
	}
	if got := RedactURL("mysql://app:secret@h:3306/db"); strings.Contains(got, "secret") {
		t.Errorf("RedactURL left the password in %s", got)
	}
}

// Definers become CURRENT_USER on schema lines and nowhere else.
func TestDefinerRewriter(t *testing.T) {
	in := strings.Join([]string{
		"/*!50013 DEFINER=`app`@`%` SQL SECURITY DEFINER */",
		"CREATE DEFINER=`o``dd`@`10.0.0.%` PROCEDURE `p`()",
		"INSERT INTO `notes` VALUES (1,'DEFINER=`app`@`%` stays, it is data');",
		strings.Repeat("x", 3<<20) + " DEFINER=`big`@`h`", // a long non-data line
		"",
	}, "\n")
	r := newDefinerRewriter(strings.NewReader(in))
	var out strings.Builder
	buf := make([]byte, 7)
	for {
		n, err := r.Read(buf)
		out.Write(buf[:n])
		if err != nil {
			break
		}
	}
	got := out.String()
	for _, want := range []string{
		"/*!50013 DEFINER=CURRENT_USER SQL SECURITY DEFINER */",
		"CREATE DEFINER=CURRENT_USER PROCEDURE",
		"'DEFINER=`app`@`%` stays, it is data'",
		" DEFINER=CURRENT_USER\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q", want)
		}
	}
	if r.rewritten != 3 {
		t.Errorf("rewrote %d definers, want 3", r.rewritten)
	}
	if len(got) != len(in)-len("`app`@`%`")-len("`o``dd`@`10.0.0.%`")-len("`big`@`h`")+3*len("CURRENT_USER") {
		t.Errorf("output length %d does not account for exactly three rewrites", len(got))
	}
}
