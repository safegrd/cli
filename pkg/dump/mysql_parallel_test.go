package dump

import (
	"database/sql"
	"strings"
	"testing"
)

func TestAMySQLRowIsWrittenAsTheDumpToolWritesIt(t *testing.T) {
	vals := []sql.RawBytes{nil, sql.RawBytes("-12.50"), sql.RawBytes{0x00, 0x27, 0x5c, 0xff}, sql.RawBytes{},
		sql.RawBytes("a'b\"c\\d\ne\rf\x00g\x1ah"), sql.RawBytes("2026-10-22 04:00:00.123456"), sql.RawBytes("\U0001F600")}
	kinds := []mysqlValueKind{mysqlQuoted, mysqlBare, mysqlHex, mysqlHex, mysqlQuoted, mysqlQuoted, mysqlQuoted}
	got := string(appendMySQLTuple(nil, vals, kinds))
	want := `(NULL,-12.50,0x00275CFF,'','a\'b\"c\\d\ne\rf\0g\Zh','2026-10-22 04:00:00.123456','` + "\U0001F600" + `')`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	for typ, want := range map[string]mysqlValueKind{"INT": mysqlBare, "UNSIGNED BIGINT": mysqlBare, "DECIMAL": mysqlBare, "YEAR": mysqlBare,
		"BIT": mysqlHex, "VARBINARY": mysqlHex, "BLOB": mysqlHex, "GEOMETRY": mysqlHex,
		"VARCHAR": mysqlQuoted, "TEXT": mysqlQuoted, "JSON": mysqlQuoted, "ENUM": mysqlQuoted, "TIMESTAMP": mysqlQuoted, "POINT": mysqlQuoted} {
		if got := mysqlKindOf(typ); got != want {
			t.Errorf("%s: kind %d, want %d", typ, got, want)
		}
	}
	if got := mysqlIdent("we`ird"); got != "`we``ird`" {
		t.Errorf("mysqlIdent: %s", got)
	}
}

// The rows go after the table's structure and before its triggers, and the
// counter every reader of a dump uses counts them.
func TestTheRowsGoWhereTheDumpToolPutsThem(t *testing.T) {
	section := "--\n-- Table structure for table `t1`\n--\n\nDROP TABLE IF EXISTS `t1`;\nCREATE TABLE `t1` (\n  `id` int NOT NULL\n) ENGINE=InnoDB;\n" +
		mysqlDataAfter + "\n/*!50003 SET @saved_cs_client      = @@character_set_client */ ;\nDELIMITER ;;\n/*!50003 CREATE*/ /*!50003 TRIGGER `x` AFTER INSERT ON `t1` FOR EACH ROW INSERT INTO `t1` VALUES (1),(2) */;;\nDELIMITER ;\n"
	at := strings.Index(section, mysqlDataAfter) + len(mysqlDataAfter) + 1
	var b strings.Builder
	b.WriteString(section[:at])
	b.WriteString("--\n-- Dumping data for table `t1`\n--\n\nLOCK TABLES `t1` WRITE;\n")
	b.Write(append(append([]byte("INSERT INTO `t1` (`id`) VALUES "), appendMySQLTuple(nil, []sql.RawBytes{sql.RawBytes("1")}, []mysqlValueKind{mysqlBare})...), ",(2),(3);\n"...))
	b.WriteString("UNLOCK TABLES;\n\n")
	b.WriteString(section[at:])
	c := newMySQLDumpCounter()
	if _, err := c.Write([]byte(b.String())); err != nil {
		t.Fatal(err)
	}
	if c.Rows["t1"] != 3 {
		t.Fatalf("the counter read %d rows of t1, want 3:\n%s", c.Rows["t1"], b.String())
	}
}
