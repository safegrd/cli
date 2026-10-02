package dump

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pg_dump 17 writes SET transaction_timeout, which PostgreSQL 16 rejects, and
// load.sql runs under ON_ERROR_STOP. Each SET has to become a set_config that
// runs only where the setting exists, with its value unquoted once.
func TestPortableSQLGuardsEverySessionSet(t *testing.T) {
	in := "SET transaction_timeout = 0;\nSET client_encoding = 'UTF8';\nSET default_tablespace = '';\n" +
		"SET x = 'it''s';\nCOMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';\nCREATE TABLE t (id int);\n"
	out := portableSQL(in)
	for _, want := range []string{
		"SELECT pg_catalog.set_config('transaction_timeout', '0', false) FROM pg_catalog.pg_settings WHERE name = 'transaction_timeout';",
		"set_config('client_encoding', 'UTF8', false)",
		"set_config('default_tablespace', '', false)",
		"set_config('x', 'it''s', false)",
		"CREATE TABLE t (id int);",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("portableSQL output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\nSET ") || strings.HasPrefix(out, "SET ") || strings.Contains(out, "COMMENT ON EXTENSION") {
		t.Errorf("a bare SET or an extension comment survived:\n%s", out)
	}
}

func TestCountBinaryCopyRows(t *testing.T) {
	var b bytes.Buffer
	b.WriteString("PGCOPY\n\xff\r\n\x00")
	_ = binary.Write(&b, binary.BigEndian, uint32(0))
	_ = binary.Write(&b, binary.BigEndian, uint32(0))
	for i := 0; i < 3; i++ {
		_ = binary.Write(&b, binary.BigEndian, int16(2))
		_ = binary.Write(&b, binary.BigEndian, int32(4))
		_ = binary.Write(&b, binary.BigEndian, int32(i))
		_ = binary.Write(&b, binary.BigEndian, int32(-1)) // NULL
	}
	whole := append([]byte(nil), b.Bytes()...)
	_ = binary.Write(&b, binary.BigEndian, int16(-1))

	dir := t.TempDir()
	path := filepath.Join(dir, "t.copy")
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if n, err := countBinaryCopyRows(path); err != nil || n != 3 {
		t.Fatalf("counted %d rows, err %v; want 3", n, err)
	}
	// A stream cut before its trailer is an error, not a short count.
	if err := os.WriteFile(path, whole[:len(whole)-3], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := countBinaryCopyRows(path); err == nil {
		t.Fatal("a truncated COPY stream was counted without an error")
	}
}
