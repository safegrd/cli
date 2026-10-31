package dump

import (
	"io"
	"strings"
	"testing"
)

// A table's section loaded alone never drops the table; loaded into a
// table the target has, it carries the rows alone: no CREATE TABLE, no
// triggers, and the data lines pass through untouched.
func TestATableSectionLoadedAloneKeepsTheTargetsTable(t *testing.T) {
	section := strings.Join([]string{
		"--",
		"-- Table structure for table `orders`",
		"--",
		"",
		"DROP TABLE IF EXISTS `orders`;",
		"/*!40101 SET @saved_cs_client     = @@character_set_client */;",
		"CREATE TABLE `orders` (",
		"  `id` int NOT NULL,",
		"  PRIMARY KEY (`id`)",
		") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
		"/*!40101 SET character_set_client = @saved_cs_client */;",
		"",
		"LOCK TABLES `orders` WRITE;",
		"INSERT INTO `orders` VALUES (1),(2);",
		"UNLOCK TABLES;",
		"/*!50003 SET @saved_cs_client      = @@character_set_client */ ;",
		"DELIMITER ;;",
		"/*!50003 CREATE*/ /*!50017 DEFINER=`app`@`%`*/ /*!50003 TRIGGER touch AFTER INSERT ON orders FOR EACH ROW UPDATE other SET id = id */;;",
		"DELIMITER ;",
		"/*!50003 SET sql_mode              = @saved_sql_mode */ ;",
		"",
	}, "\n")
	read := func(dropTable, rowsOnly bool) string {
		d := newDefinerRewriter(strings.NewReader(section))
		d.dropLocks, d.dropTable, d.skipStructure = true, dropTable, rowsOnly
		out, err := io.ReadAll(d)
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	whole := read(false, false)
	if !strings.Contains(whole, "DROP TABLE IF EXISTS") || !strings.Contains(whole, "CREATE TABLE `orders`") || !strings.Contains(whole, "DEFINER=CURRENT_USER") {
		t.Errorf("the untouched section:\n%s", whole)
	}
	created := read(true, false)
	if strings.Contains(created, "DROP TABLE") || !strings.Contains(created, "CREATE TABLE `orders` (\n  `id` int NOT NULL,") || !strings.Contains(created, "TRIGGER touch") || !strings.Contains(created, "INSERT INTO `orders` VALUES (1),(2);") {
		t.Errorf("a table loaded alone into a database that lacks it:\n%s", created)
	}
	if strings.Contains(created, "LOCK TABLES") {
		t.Errorf("the lock lines stayed:\n%s", created)
	}
	rows := read(true, true)
	for _, gone := range []string{"DROP TABLE", "CREATE TABLE", "PRIMARY KEY", "ENGINE=InnoDB", "DELIMITER", "TRIGGER touch"} {
		if strings.Contains(rows, gone) {
			t.Errorf("rows alone still carry %q:\n%s", gone, rows)
		}
	}
	for _, kept := range []string{"INSERT INTO `orders` VALUES (1),(2);", "/*!40101 SET @saved_cs_client", "/*!50003 SET sql_mode"} {
		if !strings.Contains(rows, kept) {
			t.Errorf("rows alone lost %q:\n%s", kept, rows)
		}
	}
}
