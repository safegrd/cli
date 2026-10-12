package dump

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/safegrd/cli/pkg/model"
)

// testdata/mongo-shop.archive is a real `mongodump --archive` of a MongoDB 7
// database: orders (3 documents), customers (1), empty (0) and a view.
func TestReadMongoArchive(t *testing.T) {
	raw, err := os.ReadFile("testdata/mongo-shop.archive")
	if err != nil {
		t.Fatal(err)
	}
	st, err := readMongoArchive(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if st.Docs["shop.orders"] != 3 || st.Docs["shop.customers"] != 1 || st.Docs["shop.empty"] != 0 {
		t.Errorf("counts %v", st.Docs)
	}
	if strings.Join(st.Views, ",") != "shop.v" || len(st.Collections) != 3 {
		t.Errorf("collections %v, views %v", st.Collections, st.Views)
	}
	if len(st.missingEnds()) != 0 || len(st.CRCFailed) != 0 {
		t.Errorf("a good archive: unfinished %v, CRC %v", st.missingEnds(), st.CRCFailed)
	}
	if st.ServerVersion != "7.0.43" {
		t.Errorf("server version %q", st.ServerVersion)
	}
	// Each collection's shape: its top-level fields across every document,
	// _id the primary key, a field every document carries not null, and a
	// field whose documents disagree on the type "mixed".
	cols := st.Shapes["shop.orders"].columns()
	if len(cols) == 0 || cols[0].Name != "_id" || !cols[0].PrimaryKey || !cols[0].NotNull {
		t.Fatalf("orders' shape does not start with _id as the primary key: %+v", cols)
	}
	byName := map[string]model.ColumnStat{}
	for _, c := range cols {
		byName[c.Name] = c
	}
	if a, ok := byName["a"]; !ok || a.PrimaryKey {
		t.Errorf("orders' field a: %+v", a)
	}
	if st.Shapes["shop.empty"].columns() != nil {
		t.Errorf("an empty collection has a shape: %+v", st.Shapes["shop.empty"].columns())
	}
	if h := model.ColumnsHash(cols); h == "" || h != model.ColumnsHash(st.Shapes["shop.orders"].columns()) {
		t.Errorf("the shape's hash is not stable: %q", h)
	}

	// A shape built by hand: a field one document lacks is nullable, a
	// field two documents type differently is mixed, and a document with
	// more keys than the cap leaves the shape unhashed.
	sh := &mongoShape{fields: map[string]*mongoField{}}
	doc := func(pairs ...any) bson.Raw {
		d := bson.D{}
		for i := 0; i < len(pairs); i += 2 {
			d = append(d, bson.E{Key: pairs[i].(string), Value: pairs[i+1]})
		}
		raw, err := bson.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	sh.add(doc("_id", int32(1), "n", int32(1), "note", "x"))
	sh.add(doc("_id", int32(2), "n", "two"))
	got := sh.columns()
	want := []model.ColumnStat{{Name: "_id", Type: "32-bit integer", NotNull: true, PrimaryKey: true}, {Name: "n", Type: "mixed", NotNull: true}, {Name: "note", Type: "string"}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("the shape by hand:\n got %+v\nwant %+v", got, want)
	}
	wide := bson.D{}
	for i := 0; i < mongoShapeMaxFields+1; i++ {
		wide = append(wide, bson.E{Key: fmt.Sprintf("k%d", i), Value: int32(i)})
	}
	wideRaw, _ := bson.Marshal(wide)
	sh.add(wideRaw)
	if !sh.capped || len(sh.columns()) != mongoShapeMaxFields {
		t.Errorf("a document past the cap: capped=%v, %d columns", sh.capped, len(sh.columns()))
	}

	// Cut short: the namespaces that did not finish are named.
	cut, _ := readMongoArchive(bytes.NewReader(raw[:1300]))
	if cut == nil || len(cut.missingEnds()) == 0 {
		t.Error("a truncated archive looked complete")
	}

	// One byte of one document changed: its collection's CRC no longer holds.
	bad := append([]byte(nil), raw...)
	i := bytes.Index(bad, []byte("\x10a\x00\x02\x00\x00\x00")) // orders' {a: 2}
	if i < 0 {
		t.Fatal("fixture changed")
	}
	bad[i+3] = 9
	st, err = readMongoArchive(bytes.NewReader(bad))
	if err != nil || strings.Join(st.CRCFailed, ",") != "shop.orders" {
		t.Errorf("a changed document passed its CRC: %v %v", st.CRCFailed, err)
	}
}

func TestMongoURLs(t *testing.T) {
	if db, err := mongoDatabase("mongodb://u:p@h:27017/shop?authSource=admin"); err != nil || db != "shop" {
		t.Errorf("%q %v", db, err)
	}
	if _, err := mongoDatabase("mongodb://h:27017/"); err == nil {
		t.Error("a URL with no database was accepted")
	}
	if !SameMongoDatabase("mongodb://a@localhost/x", "mongodb://b:pw@127.0.0.1:27017/x?tls=true") || SameMongoDatabase("mongodb://h/x", "mongodb://h/y") {
		t.Error("SameMongoDatabase")
	}
	if got := RedactURL("mongodb://app:secret@h:27017/db"); strings.Contains(got, "secret") {
		t.Errorf("RedactURL left the password in %s", got)
	}
}
