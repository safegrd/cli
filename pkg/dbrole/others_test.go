package dbrole

import (
	"strings"
	"testing"
)

// The grants mysqldump needs to read, and nothing more, write nothing; any
// grant that changes data or schema is named with where it applies.
func TestMySQLWritesNamesWhatAnAccountCanChange(t *testing.T) {
	reader := []string{
		"GRANT USAGE ON *.* TO `reader`@`%`",
		"GRANT SHOW_ROUTINE ON *.* TO `reader`@`%`",
		"GRANT SELECT, LOCK TABLES, SHOW VIEW, EVENT, TRIGGER ON `shop`.* TO `reader`@`%`",
		"GRANT `app_role`@`%` TO `reader`@`%`",
	}
	if got := MySQLWrites(reader); len(got) != 0 {
		t.Errorf("a read-only account writes %v", got)
	}
	writer := []string{
		"GRANT USAGE ON *.* TO `app`@`%`",
		"GRANT ALL PRIVILEGES ON `shop`.* TO `app`@`%`",
		"GRANT SELECT, INSERT, UPDATE (`note`) ON `other`.`notes` TO `app`@`%`",
	}
	got := strings.Join(MySQLWrites(writer), "; ")
	if got != "ALL PRIVILEGES on `shop`.*; INSERT, UPDATE on `other`.`notes`" {
		t.Errorf("an account that writes: %q", got)
	}
}

func TestMongoWritesNamesRolesThatCanChangeSomething(t *testing.T) {
	if got := MongoWrites([]MongoRole{{"read", "shop"}, {"backup", "admin"}, {"readAnyDatabase", "admin"}}); len(got) != 0 {
		t.Errorf("read roles write %v", got)
	}
	got := strings.Join(MongoWrites([]MongoRole{{"readWrite", "shop"}, {"read", "logs"}, {"root", "admin"}}), "; ")
	if got != "readWrite on shop; root on admin" {
		t.Errorf("roles that write: %q", got)
	}
}
