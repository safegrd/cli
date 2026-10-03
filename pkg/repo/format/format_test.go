package format

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"
)

func u32(v uint32) *uint32 { return &v }

func mustID(t *testing.T, s string) ID {
	t.Helper()
	return Hash([]byte(s))
}

// The bytes of a tree blob are frozen: a tree's id is their hash, so an
// encoder that changed them would make every unchanged directory look new.
func TestTreeEncodingIsFrozen(t *testing.T) {
	mt := time.Date(2026, 10, 1, 2, 0, 3, 112000000, time.UTC)
	sub := mustID(t, "sub")
	c1 := mustID(t, "c1")
	tr := Tree{Entries: []Node{
		{Name: "etc", Type: NodeDir, Mode: 0o755, UID: u32(0), GID: u32(0), ModTime: mt, Subtree: sub},
		{Name: "hosts", Type: NodeFile, Mode: 0o644, UID: u32(0), GID: u32(0), ModTime: mt, Size: 221,
			SHA256: strings.Repeat("ab", 32), Content: []ID{c1}},
		{Name: "link", Type: NodeSymlink, Mode: 0o777, ModTime: mt, Target: "hosts <&>"},
		{Name: "zero", Type: NodeFile, Mode: 0o600, ModTime: mt, SHA256: hex.EncodeToString(sha256.New().Sum(nil)), Content: nil},
	}}
	got, err := EncodeTree(tr)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"entries":[` +
		`{"name":"etc","type":"dir","mode":493,"uid":0,"gid":0,"mtime":"2026-10-01T02:00:03.112Z","subtree":"` + sub.String() + `"},` +
		`{"name":"hosts","type":"file","mode":420,"uid":0,"gid":0,"mtime":"2026-10-01T02:00:03.112Z","size":221,"sha256":"` + strings.Repeat("ab", 32) + `","content":["` + c1.String() + `"]},` +
		`{"name":"link","type":"symlink","mode":511,"mtime":"2026-10-01T02:00:03.112Z","target":"hosts <&>"},` +
		`{"name":"zero","type":"file","mode":384,"mtime":"2026-10-01T02:00:03.112Z","size":0,"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","content":[]}` +
		`]}`
	if string(got) != want {
		t.Fatalf("tree bytes changed:\n got %s\nwant %s", got, want)
	}
	back, err := DecodeTree(got)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := EncodeTree(back)
	if !bytes.Equal(again, got) {
		t.Fatalf("decode then encode is not the identity:\n%s\n%s", again, got)
	}
}

func TestTreeNamesThatAreNotUTF8RoundTripAsBase64(t *testing.T) {
	mt := time.Unix(0, 0)
	bad := "caf\xe9"
	tr := Tree{Entries: []Node{
		{Name: "a", Type: NodeSymlink, Mode: 0o777, ModTime: mt, Target: "\xff\xfe"},
		{Name: bad, Type: NodeFile, Mode: 0o644, ModTime: mt, SHA256: strings.Repeat("0", 64)},
	}}
	b, err := EncodeTree(tr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"name_b64":"Y2Fm6Q=="`) || !strings.Contains(string(b), `"target_b64":"//4="`) {
		t.Fatalf("raw bytes not written as base64: %s", b)
	}
	back, err := DecodeTree(b)
	if err != nil {
		t.Fatal(err)
	}
	if back.Entries[1].Name != bad || back.Entries[0].Target != "\xff\xfe" {
		t.Fatalf("raw bytes lost: %q %q", back.Entries[1].Name, back.Entries[0].Target)
	}
}

func TestTreeRefusesWhatAReaderWouldRefuse(t *testing.T) {
	mt := time.Unix(0, 0)
	f := func(name string) Node {
		return Node{Name: name, Type: NodeFile, ModTime: mt, SHA256: strings.Repeat("0", 64)}
	}
	cases := map[string]Tree{
		"unsorted":       {Entries: []Node{f("b"), f("a")}},
		"repeated":       {Entries: []Node{f("a"), f("a")}},
		"slash":          {Entries: []Node{f("a/b")}},
		"dotdot":         {Entries: []Node{f("..")}},
		"empty name":     {Entries: []Node{f("")}},
		"nul":            {Entries: []Node{f("a\x00")}},
		"mode bits":      {Entries: []Node{{Name: "a", Type: NodeFile, Mode: 0o10000, ModTime: mt, SHA256: strings.Repeat("0", 64)}}},
		"dir no subtree": {Entries: []Node{{Name: "a", Type: NodeDir, ModTime: mt}}},
		"file no hash":   {Entries: []Node{{Name: "a", Type: NodeFile, ModTime: mt}}},
		"data no blobs":  {Entries: []Node{{Name: "a", Type: NodeFile, Size: 3, ModTime: mt, SHA256: strings.Repeat("0", 64)}}},
		"link no target": {Entries: []Node{{Name: "a", Type: NodeSymlink, ModTime: mt}}},
		"socket":         {Entries: []Node{{Name: "a", Type: "socket", ModTime: mt}}},
	}
	for name, tr := range cases {
		if _, err := EncodeTree(tr); err == nil {
			t.Errorf("%s: encoded", name)
		}
	}
	// Byte order, not string collation: "B" (0x42) sorts before "a" (0x61).
	if _, err := EncodeTree(Tree{Entries: []Node{f("B"), f("a"), f("\xc3\xa9")}}); err != nil {
		t.Errorf("raw byte order refused: %v", err)
	}
	for name, js := range map[string]string{
		"unknown key":     `{"entries":[],"extra":1}`,
		"no entries":      `{}`,
		"trailing":        `{"entries":[]} {}`,
		"dir with size":   `{"entries":[{"name":"a","type":"dir","mode":0,"mtime":"2026-01-01T00:00:00Z","size":1,"subtree":"` + strings.Repeat("0", 63) + `1"}]}`,
		"upper hex":       `{"entries":[{"name":"a","type":"dir","mode":0,"mtime":"2026-01-01T00:00:00Z","subtree":"` + strings.Repeat("A", 64) + `"}]}`,
		"both names":      `{"entries":[{"name":"a","name_b64":"YQ==","type":"symlink","mode":0,"mtime":"2026-01-01T00:00:00Z","target":"x"}]}`,
		"b64 of utf8":     `{"entries":[{"name_b64":"YQ==","type":"symlink","mode":0,"mtime":"2026-01-01T00:00:00Z","target":"x"}]}`,
		"bad mtime":       `{"entries":[{"name":"a","type":"symlink","mode":0,"mtime":"yesterday","target":"x"}]}`,
		"link with sha":   `{"entries":[{"name":"a","type":"symlink","mode":0,"mtime":"2026-01-01T00:00:00Z","sha256":"` + strings.Repeat("0", 64) + `","target":"x"}]}`,
		"negative size":   `{"entries":[{"name":"a","type":"file","mode":0,"mtime":"2026-01-01T00:00:00Z","size":-1,"sha256":"` + strings.Repeat("0", 64) + `","content":[]}]}`,
		"content not ids": `{"entries":[{"name":"a","type":"file","mode":0,"mtime":"2026-01-01T00:00:00Z","size":1,"sha256":"` + strings.Repeat("0", 64) + `","content":["x"]}]}`,
	} {
		if _, err := DecodeTree([]byte(js)); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
}

// contentRootFromSpec is a second implementation of the content root,
// written from the format's text alone: one line "<type> SP <value> SP
// <path> LF" per entry, sorted by the raw bytes of the path before escaping,
// with bytes outside 0x21–0x7e and "%" as %XX.
func contentRootFromSpec(entries map[string][2]string) string {
	paths := make([]string, 0, len(entries))
	for p := range entries {
		paths = append(paths, p)
	}
	sort.Slice(paths, func(i, j int) bool { return bytes.Compare([]byte(paths[i]), []byte(paths[j])) < 0 })
	h := sha256.New()
	for _, p := range paths {
		var esc strings.Builder
		for _, c := range []byte(p) {
			if c >= 0x21 && c <= 0x7e && c != '%' {
				esc.WriteByte(c)
			} else {
				esc.WriteString(fmt.Sprintf("%%%02X", c))
			}
		}
		e := entries[p]
		fmt.Fprintf(h, "%s %s %s\n", e[0], e[1], esc.String())
	}
	return hex.EncodeToString(h.Sum(nil))
}

func TestContentRootAgreesWithTheSpec(t *testing.T) {
	entries := map[string][2]string{
		"a":            {"d", "-"},
		"a/b":          {"f", strings.Repeat("1", 64)},
		"a-c":          {"f", strings.Repeat("2", 64)},
		"a b%c":        {"l", hex.EncodeToString([]byte("../x"))},
		"caf\xe9":      {"f", strings.Repeat("3", 64)},
		"Z":            {"d", "-"},
		"a/\nnewline":  {"f", strings.Repeat("4", 64)},
		"a/\x7fdelete": {"l", hex.EncodeToString([]byte("\xff"))},
	}
	paths := make([]string, 0, len(entries))
	for p := range entries {
		paths = append(paths, p)
	}
	sort.Slice(paths, func(i, j int) bool { return bytes.Compare([]byte(paths[i]), []byte(paths[j])) < 0 })
	cr := NewContentRoot()
	for _, p := range paths {
		e := entries[p]
		cr.Add(e[0][0], e[1], p)
	}
	got, err := cr.Sum()
	if err != nil {
		t.Fatal(err)
	}
	if want := contentRootFromSpec(entries); got != want {
		t.Fatalf("content root %s, the spec gives %s", got, want)
	}
	if empty, _ := NewContentRoot().Sum(); empty != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("empty root %s", empty)
	}
	// Depth-first order is not byte order: "a/b" sorts after "a-c".
	cr = NewContentRoot()
	cr.Add('d', "-", "a")
	cr.Add('f', strings.Repeat("1", 64), "a/b")
	cr.Add('f', strings.Repeat("2", 64), "a-c")
	if _, err := cr.Sum(); err == nil {
		t.Fatal("a walk-ordered list was accepted")
	}
}

func TestEscapePath(t *testing.T) {
	for in, want := range map[string]string{
		"etc/hosts":   "etc/hosts",
		"a b":         "a%20b",
		"100%":        "100%25",
		"caf\xc3\xa9": "caf%C3%A9",
		"~!":          "~!",
		"\x7f":        "%7F",
	} {
		if got := EscapePath(in); got != want {
			t.Errorf("EscapePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPackHeaderAndFooterBytesAreFrozen(t *testing.T) {
	h, err := EncodePackHeader([]byte("WRAPPED"))
	if err != nil {
		t.Fatal(err)
	}
	if want := "5347504b01000000070000005752415050454" + "4"; hex.EncodeToString(h) != want {
		t.Fatalf("header %x, want %s", h, want)
	}
	w, n, err := ParsePackHeader(h)
	if err != nil || string(w) != "WRAPPED" || n != 19 {
		t.Fatalf("parse: %q %d %v", w, n, err)
	}
	f := EncodePackFooter(300)
	if hex.EncodeToString(f) != "2c0100005347504b" {
		t.Fatalf("footer %x", f)
	}
	if tl, err := ParsePackFooter(f, 19+300+8, 19); err != nil || tl != 300 {
		t.Fatalf("footer parse %d %v", tl, err)
	}
	if _, err := ParsePackFooter(f, 19+299+8, 19); err == nil {
		t.Fatal("a trailer longer than the pack was accepted")
	}
	bad := append([]byte{}, h...)
	bad[4] = 2
	if _, _, err := ParsePackHeader(bad); err == nil || !strings.Contains(err.Error(), "version 2") {
		t.Fatalf("version 2 not refused by name: %v", err)
	}
	bad = append([]byte{}, h...)
	bad[6] = 1
	if _, _, err := ParsePackHeader(bad); err == nil {
		t.Fatal("non-zero reserved bytes accepted")
	}
}

func TestTrailerRoundTripAndRefusals(t *testing.T) {
	id := mustID(t, "x").String()
	tr := Trailer{Blobs: []BlobEntry{{ID: id, Type: BlobData | Compressed, Offset: 300, Length: 100, RawLength: 500}}}
	b, err := EncodeTrailer(tr)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"blobs":[{"id":"` + id + `","type":128,"offset":300,"length":100,"raw_length":500}]}`; string(b) != want {
		t.Fatalf("trailer bytes %s", b)
	}
	if _, err := DecodeTrailer(b); err != nil {
		t.Fatal(err)
	}
	for name, e := range map[string]BlobEntry{
		"trailer type": {ID: id, Type: BlobTrailer, Offset: 300, Length: 100},
		"type 2":       {ID: id, Type: 2, Offset: 300, Length: 100},
		"in header":    {ID: id, Type: 0, Offset: 4, Length: 100, RawLength: 60},
		"short":        {ID: id, Type: 0, Offset: 300, Length: 39},
		"raw mismatch": {ID: id, Type: 0, Offset: 300, Length: 100, RawLength: 61},
		"negative raw": {ID: id, Type: 128, Offset: 300, Length: 100, RawLength: -1},
	} {
		if err := e.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	overlap := Trailer{Blobs: []BlobEntry{
		{ID: id, Type: 0, Offset: 300, Length: 100, RawLength: 60},
		{ID: id, Type: 0, Offset: 350, Length: 100, RawLength: 60},
	}}
	b, _ = EncodeTrailer(overlap)
	if _, err := DecodeTrailer(b); err == nil {
		t.Fatal("overlapping records accepted")
	}
}

func TestEpochDescriptorKeyOrder(t *testing.T) {
	at := time.Date(2026, 10, 1, 2, 0, 3, 112000000, time.UTC)
	e := Epoch{Format: FormatName, Version: 1, EpochID: "e202610-3fa94c1d", SurfaceID: "srf-1", OpenedAt: at,
		PlannedEnd: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), Reason: ReasonMonth, TMidDays: 28, OpeningTier: TierMonthly,
		OpeningRetainUntil: time.Date(2027, 10, 4, 2, 0, 3, 0, time.UTC), LaterRetainUntil: time.Date(2026, 11, 29, 0, 0, 0, 0, time.UTC),
		Recipient: "age1x", Chunker: DefaultChunker, PackTargetBytes: DefaultPackTarget}
	b, err := Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"format":"safegrd-repo","version":1,"epoch_id":"e202610-3fa94c1d","surface_id":"srf-1",` +
		`"opened_at":"2026-10-01T02:00:03.112Z","planned_end":"2026-11-01T00:00:00Z","reason":"month","t_mid_days":28,` +
		`"opening_tier":"monthly","opening_retain_until":"2027-10-04T02:00:03Z","later_retain_until":"2026-11-29T00:00:00Z",` +
		`"recipient":"age1x","chunker":{"algorithm":"rabin-restic","min":524288,"avg":1048576,"max":8388608},"pack_target_bytes":33554432}`
	if string(b) != want {
		t.Fatalf("epoch.json:\n got %s\nwant %s", b, want)
	}
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	e.Version = 2
	if err := e.Validate(); err == nil || !strings.Contains(err.Error(), "version 2") {
		t.Fatalf("version 2 not refused by name: %v", err)
	}
}

func TestIndexValidate(t *testing.T) {
	id := mustID(t, "x").String()
	x := Index{Version: 1, EpochID: "e202610-3fa94c1d", RunID: strings.Repeat("a", 32), Packs: []IndexPack{
		{PackID: strings.Repeat("b", 32), Bytes: 1000, Blobs: []BlobEntry{{ID: id, Type: 1, Offset: 300, Length: 100, RawLength: 60}}},
	}}
	if err := x.Validate(); err != nil {
		t.Fatal(err)
	}
	x.Packs[0].Bytes = 350
	if err := x.Validate(); err == nil {
		t.Fatal("a blob past its pack's end accepted")
	}
}
