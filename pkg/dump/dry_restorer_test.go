package dump

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/safegrd/cli/pkg/model"
)

// buildSyntheticPgCopyBinary creates a valid PostgreSQL binary COPY byte stream for test tuples.
func buildSyntheticPgCopyBinary(tuples [][]string) []byte {
	var buf bytes.Buffer

	// 1. Signature (11 bytes)
	buf.Write(pgCopySignature)

	// 2. Flags (4 bytes, 0 = no OIDs)
	_ = binary.Write(&buf, binary.BigEndian, uint32(0))

	// 3. Header extension length (4 bytes, 0 = none)
	_ = binary.Write(&buf, binary.BigEndian, uint32(0))

	// 4. Write tuples
	for _, row := range tuples {
		// Field count (int16)
		_ = binary.Write(&buf, binary.BigEndian, int16(len(row)))
		for _, colVal := range row {
			valBytes := []byte(colVal)
			// Field length (int32)
			_ = binary.Write(&buf, binary.BigEndian, int32(len(valBytes)))
			buf.Write(valBytes)
		}
	}

	// 5. File trailer: -1 (int16)
	_ = binary.Write(&buf, binary.BigEndian, int16(-1))

	return buf.Bytes()
}

func TestDryRestorer_InspectArchive_Success(t *testing.T) {
	ctx := context.Background()

	// 1. Prepare synthetic manifest
	manifest := model.SnapshotMetadata{
		SnapshotID:   "snap-test-dry-01",
		DatabaseName: "production_db",
		SchemaSource: "pg_dump 18.6",
		CreatedAt:    time.Now().UTC(),
		Status:       model.SnapshotStatusCompleted,
		TotalTables:  2,
		TotalRows:    5,
		Extensions:   []string{"pgcrypto", "uuid-ossp"},
		TableStats: []model.TableStat{
			{Schema: "public", TableName: "users", RowCount: 3, SizeBytes: 150},
			{Schema: "public", TableName: "orders", RowCount: 2, SizeBytes: 120},
		},
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("failed marshaling manifest: %v", err)
	}

	// 2. Prepare synthetic schema DDL
	schemaSQL := `
-- Extensions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Table: public.users
CREATE TABLE IF NOT EXISTS "public"."users" (
  "id" integer NOT NULL,
  "email" character varying(255) NOT NULL,
  "created_at" timestamp without time zone DEFAULT now()
);

-- Table: public.orders
CREATE TABLE IF NOT EXISTS "public"."orders" (
  "id" integer NOT NULL,
  "user_id" integer NOT NULL,
  "amount_cents" bigint NOT NULL,
  "status" character varying(50) DEFAULT 'pending'
);
`

	// 3. Prepare synthetic PGCOPY binary streams
	usersCopy := buildSyntheticPgCopyBinary([][]string{
		{"1", "alice@example.com", "2026-01-01 10:00:00"},
		{"2", "bob@example.com", "2026-01-02 11:00:00"},
		{"3", "charlie@example.com", "2026-01-03 12:00:00"},
	})

	ordersCopy := buildSyntheticPgCopyBinary([][]string{
		{"101", "1", "4900", "completed"},
		{"102", "2", "8900", "completed"},
	})

	// 4. Pack into tar archive
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)

	addEntry := func(name string, data []byte) {
		hdr := &tar.Header{
			Name: name,
			Mode: 0644,
			Size: int64(len(data)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("failed writing header %s: %v", name, err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatalf("failed writing data %s: %v", name, err)
		}
	}

	// The layout Dump writes: schema, rows (users split across two chunks,
	// as a table larger than copyChunkSize is), sequences, manifest last.
	addEntry("pre-data.sql", []byte(schemaSQL))
	addEntry("data/public/users.copy", usersCopy[:17])
	addEntry("data/public/users.copy.1", usersCopy[17:])
	addEntry("data/public/orders.copy", ordersCopy)
	addEntry("post-data.sql", []byte("ALTER TABLE ONLY public.users ADD CONSTRAINT users_pkey PRIMARY KEY (id);\n"))
	addEntry("sequences.sql", []byte("-- none\n"))
	addEntry("manifest.json", manifestBytes)
	_ = tw.Close()

	// 5. Run DryRestorer
	restorer := NewDryRestorer()
	res, err := restorer.InspectArchive(ctx, &tarBuf)
	if err != nil {
		t.Fatalf("inspect archive failed: %v", err)
	}

	if !res.Passed {
		t.Fatalf("expected dry restore to pass, but failed: %s", res.ErrorMessage)
	}

	if res.TotalTables != 2 {
		t.Errorf("expected 2 tables, got %d", res.TotalTables)
	}
	if res.TotalRows != 5 {
		t.Errorf("expected 5 rows, got %d", res.TotalRows)
	}
	if len(res.Extensions) != 2 {
		t.Errorf("expected 2 extensions, got %d", len(res.Extensions))
	}

	// Verify column extraction
	var usersStats *TableDryStats
	for _, table := range res.Tables {
		if table.TableName == "users" {
			usersStats = &table
			break
		}
	}
	if usersStats == nil {
		t.Fatalf("expected table users in dry stats")
	}
	if usersStats.ColumnCount != 3 {
		t.Errorf("expected users to have 3 columns, got %d", usersStats.ColumnCount)
	}
	if usersStats.RowCount != 3 {
		t.Errorf("expected users to have 3 rows, got %d", usersStats.RowCount)
	}
}

func TestDryRestorer_InspectArchive_RowMismatchFailure(t *testing.T) {
	ctx := context.Background()

	manifest := model.SnapshotMetadata{
		SnapshotID:   "snap-test-dry-02",
		DatabaseName: "production_db",
		TotalTables:  1,
		TotalRows:    100, // Manifest expects 100 rows
		TableStats: []model.TableStat{
			{Schema: "public", TableName: "items", RowCount: 100},
		},
	}
	manifestBytes, _ := json.MarshalIndent(manifest, "", "  ")

	schemaSQL := `
CREATE TABLE IF NOT EXISTS "public"."items" (
  "id" integer NOT NULL,
  "name" text
);
`
	itemsCopy := buildSyntheticPgCopyBinary([][]string{
		{"1", "widget A"},
		{"2", "widget B"},
	})

	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)

	addEntry := func(name string, data []byte) {
		hdr := &tar.Header{Name: name, Mode: 0644, Size: int64(len(data))}
		_ = tw.WriteHeader(hdr)
		_, _ = tw.Write(data)
	}

	addEntry("manifest.json", manifestBytes)
	addEntry("schema.sql", []byte(schemaSQL))
	addEntry("data/public/items.copy", itemsCopy)
	_ = tw.Close()

	restorer := NewDryRestorer()
	res, err := restorer.InspectArchive(ctx, &tarBuf)
	if err != nil {
		t.Fatalf("unexpected inspection error: %v", err)
	}

	if res.Passed {
		t.Fatalf("expected dry restore to fail due to row count mismatch, but it passed")
	}
}

// A snapshot whose schema was not captured by pg_dump fails its drill, however
// good its rows: before pg_dump captured the schema, such a schema could not restore an array column at
// all, and it never carried foreign keys, views, triggers or enum types.
func TestDryRestorer_ASchemaNotFromPgDumpFailsTheDrill(t *testing.T) {
	for _, source := range []string{"", SchemaSourceNative} {
		manifest := model.SnapshotMetadata{
			SnapshotID: "snap-legacy", SchemaSource: source, TotalTables: 1, TotalRows: 1,
			TableStats: []model.TableStat{{Schema: "public", TableName: "t", RowCount: 1}},
		}
		mb, _ := json.Marshal(manifest)
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for _, e := range []struct {
			name string
			data []byte
		}{
			{"manifest.json", mb},
			{"schema.sql", []byte(`CREATE TABLE IF NOT EXISTS "public"."t" ("id" integer);`)},
			{"data/public/t.copy", buildSyntheticPgCopyBinary([][]string{{"1"}})},
		} {
			_ = tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0644, Size: int64(len(e.data))})
			_, _ = tw.Write(e.data)
		}
		_ = tw.Close()
		res, err := NewDryRestorer().InspectArchive(context.Background(), &buf)
		if err != nil {
			t.Fatal(err)
		}
		if res.Passed {
			t.Errorf("schema_source %q: the drill passed a schema it cannot restore", source)
		}
		var saw bool
		for _, a := range res.Assertions {
			if a.Name == "Schema Captured By pg_dump" && !a.Passed && a.Message != "" {
				saw = true
			}
		}
		if !saw {
			t.Errorf("schema_source %q: no failed fidelity assertion saying why: %+v", source, res.Assertions)
		}
	}
}

// Chunks are joined only in order: a chunk out of place is an altered
// archive, and joining it would load one table's rows into another.
func TestDryRestorer_AChunkOutOfOrderIsRefused(t *testing.T) {
	copyBytes := buildSyntheticPgCopyBinary([][]string{{"1"}, {"2"}})
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range []struct {
		name string
		data []byte
	}{
		{"pre-data.sql", []byte("CREATE TABLE public.t (id integer);")},
		{"data/public/t.copy", copyBytes[:10]},
		{"data/public/t.copy.2", copyBytes[10:]},
		{"manifest.json", []byte(`{"schema_source":"pg_dump 18.6"}`)},
	} {
		_ = tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0644, Size: int64(len(e.data))})
		_, _ = tw.Write(e.data)
	}
	_ = tw.Close()
	res, err := NewDryRestorer().InspectArchive(context.Background(), &buf)
	if err != nil {
		t.Fatal(err)
	}
	if res.Passed || !strings.Contains(res.ErrorMessage, "out of order") {
		t.Fatalf("an out-of-order chunk was accepted: passed=%v %q", res.Passed, res.ErrorMessage)
	}
}

func TestCopyEntryNamesRoundTrip(t *testing.T) {
	for _, c := range []struct {
		schema, table string
		part          int
	}{{"public", "orders", 0}, {"public", "orders", 12}, {"billing", "orders.copy", 3}, {"s", "a.b", 0}} {
		name := copyEntryName(c.schema, c.table, c.part)
		s, tb, p, ok := parseCopyEntry(name)
		if !ok || s != c.schema || tb != c.table || p != c.part {
			t.Errorf("%s parsed as %q %q %d %v", name, s, tb, p, ok)
		}
	}
	for _, bad := range []string{"data/x.copy", "data/public/t.copy.0", "data/public/t.copy.x", "manifest.json", "data/a/b/c.copy"} {
		if _, _, _, ok := parseCopyEntry(bad); ok {
			t.Errorf("%s parsed as a data entry", bad)
		}
	}
}

// A table larger than one chunk is written as several entries and read back
// as the same bytes.
func TestChunkWriterSplitsAndJoins(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	payload := bytes.Repeat([]byte("0123456789abcdef"), (copyChunkSize*2+1234)/16)
	cw := newChunkWriter(tw, "public", "big")
	for i := 0; i < len(payload); i += 100000 {
		end := min(i+100000, len(payload))
		if _, err := cw.Write(payload[i:end]); err != nil {
			t.Fatal(err)
		}
	}
	if err := cw.Close(); err != nil {
		t.Fatal(err)
	}
	_ = tw.Close()
	if cw.part != 3 {
		t.Fatalf("wrote %d chunks, want 3", cw.part)
	}
	var got bytes.Buffer
	ts := &tableStreams{consume: func(schema, table string, r io.Reader) error {
		_, err := io.Copy(&got, r)
		return err
	}}
	if err := ts.Run(tar.NewReader(&buf)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("joined %d bytes, want %d", got.Len(), len(payload))
	}
}
