package dump

import (
	"bytes"
	"os"
	"strings"
	"testing"
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
