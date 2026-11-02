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
	again, err := EncodeTree(back)
	if err != nil || !bytes.Equal(again, got) {
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
	cases := map[string]struct {
		tr   Tree
		want string
	}{
		"unsorted":       {Tree{Entries: []Node{f("b"), f("a")}}, "out of order or repeated"},
		"repeated":       {Tree{Entries: []Node{f("a"), f("a")}}, "out of order or repeated"},
		"slash":          {Tree{Entries: []Node{f("a/b")}}, "holds a slash or NUL"},
		"dotdot":         {Tree{Entries: []Node{f("..")}}, `the name ".."`},
		"empty name":     {Tree{Entries: []Node{f("")}}, "an empty name"},
		"nul":            {Tree{Entries: []Node{f("a\x00")}}, "holds a slash or NUL"},
		"mode bits":      {Tree{Entries: []Node{{Name: "a", Type: NodeFile, Mode: 0o10000, ModTime: mt, SHA256: strings.Repeat("0", 64)}}}, "beyond the permission bits"},
		"dir no subtree": {Tree{Entries: []Node{{Name: "a", Type: NodeDir, ModTime: mt}}}, "has no subtree"},
		"file no hash":   {Tree{Entries: []Node{{Name: "a", Type: NodeFile, ModTime: mt}}}, "has no SHA-256"},
		"data no blobs":  {Tree{Entries: []Node{{Name: "a", Type: NodeFile, Size: 3, ModTime: mt, SHA256: strings.Repeat("0", 64)}}}, "has 3 bytes and no content"},
		"link no target": {Tree{Entries: []Node{{Name: "a", Type: NodeSymlink, ModTime: mt}}}, "has no target"},
		"socket":         {Tree{Entries: []Node{{Name: "a", Type: "socket", ModTime: mt}}}, `has type "socket"`},
	}
	for name, c := range cases {
		if _, err := EncodeTree(c.tr); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: encoded, or refused for another reason: %v (want %q)", name, err, c.want)
		}
	}
	// Byte order, not string collation: "B" (0x42) sorts before "a" (0x61).
	if _, err := EncodeTree(Tree{Entries: []Node{f("B"), f("a"), f("\xc3\xa9")}}); err != nil {
		t.Errorf("raw byte order refused: %v", err)
	}
	for name, c := range map[string]struct{ js, want string }{
		"unknown key":     {`{"entries":[],"extra":1}`, `unknown field "extra"`},
		"no entries":      {`{}`, "no entries list"},
		"trailing":        {`{"entries":[]} {}`, "unexpected data after the JSON value"},
		"dir with size":   {`{"entries":[{"name":"a","type":"dir","mode":0,"mtime":"2026-01-01T00:00:00Z","size":1,"subtree":"` + strings.Repeat("0", 63) + `1"}]}`, "directory entry 0 carries a file's or a link's field"},
		"upper hex":       {`{"entries":[{"name":"a","type":"dir","mode":0,"mtime":"2026-01-01T00:00:00Z","subtree":"` + strings.Repeat("A", 64) + `"}]}`, "is not 64 lowercase hex characters"},
		"both names":      {`{"entries":[{"name":"a","name_b64":"YQ==","type":"symlink","mode":0,"mtime":"2026-01-01T00:00:00Z","target":"x"}]}`, "has both name and name_b64"},
		"b64 of utf8":     {`{"entries":[{"name_b64":"YQ==","type":"symlink","mode":0,"mtime":"2026-01-01T00:00:00Z","target":"x"}]}`, "name_b64 holds valid UTF-8"},
		"bad mtime":       {`{"entries":[{"name":"a","type":"symlink","mode":0,"mtime":"yesterday","target":"x"}]}`, "mtime"},
		"link with sha":   {`{"entries":[{"name":"a","type":"symlink","mode":0,"mtime":"2026-01-01T00:00:00Z","sha256":"` + strings.Repeat("0", 64) + `","target":"x"}]}`, "symlink entry 0 carries a file's or a directory's field"},
		"negative size":   {`{"entries":[{"name":"a","type":"file","mode":0,"mtime":"2026-01-01T00:00:00Z","size":-1,"sha256":"` + strings.Repeat("0", 64) + `","content":[]}]}`, "has a negative size"},
		"content not ids": {`{"entries":[{"name":"a","type":"file","mode":0,"mtime":"2026-01-01T00:00:00Z","size":1,"sha256":"` + strings.Repeat("0", 64) + `","content":["x"]}]}`, `blob id "x" is not 64 lowercase hex characters`},
	} {
		if _, err := DecodeTree([]byte(c.js)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: decoded, or refused for another reason: %v (want %q)", name, err, c.want)
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
	if _, err := cr.Sum(); err == nil || !strings.Contains(err.Error(), `path "a-c" arrived after "a/b"`) {
		t.Fatalf("a walk-ordered list: %v, want it refused by order", err)
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
	if _, err := ParsePackFooter(f, 19+299+8, 19); err == nil || !strings.Contains(err.Error(), "does not fit") {
		t.Fatalf("a trailer longer than the pack: %v, want it refused as not fitting", err)
	}
	bad := append([]byte{}, h...)
	bad[4] = 2
	if _, _, err := ParsePackHeader(bad); err == nil || !strings.Contains(err.Error(), "version 2") {
		t.Fatalf("version 2 not refused by name: %v", err)
	}
	bad = append([]byte{}, h...)
	bad[6] = 1
	if _, _, err := ParsePackHeader(bad); err == nil || !strings.Contains(err.Error(), "reserved bytes are not zero") {
		t.Fatalf("non-zero reserved bytes: %v", err)
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
	for name, c := range map[string]struct {
		e    BlobEntry
		want string
	}{
		"trailer type": {BlobEntry{ID: id, Type: BlobTrailer, Offset: 300, Length: 100}, "type byte 127 is not data or tree"},
		"type 2":       {BlobEntry{ID: id, Type: 2, Offset: 300, Length: 100}, "type byte 2 is not data or tree"},
		"in header":    {BlobEntry{ID: id, Type: 0, Offset: 4, Length: 100, RawLength: 60}, "inside the pack header"},
		"short":        {BlobEntry{ID: id, Type: 0, Offset: 300, Length: 39}, "shorter than the nonce and tag"},
		"raw mismatch": {BlobEntry{ID: id, Type: 0, Offset: 300, Length: 100, RawLength: 61}, "cannot hold 61 raw bytes"},
		"negative raw": {BlobEntry{ID: id, Type: 128, Offset: 300, Length: 100, RawLength: -1}, "raw length -1 is out of range"},
	} {
		if err := c.e.Validate(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: accepted, or refused for another reason: %v (want %q)", name, err, c.want)
		}
	}
	overlap := Trailer{Blobs: []BlobEntry{
		{ID: id, Type: 0, Offset: 300, Length: 100, RawLength: 60},
		{ID: id, Type: 0, Offset: 350, Length: 100, RawLength: 60},
	}}
	if b, err = EncodeTrailer(overlap); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeTrailer(b); err == nil || !strings.Contains(err.Error(), "overlaps the one before it") {
		t.Fatalf("overlapping records: %v", err)
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
	if err := x.Validate(); err == nil || !strings.Contains(err.Error(), "ends past the pack's 350 bytes") {
		t.Fatalf("a blob past its pack's end: %v", err)
	}
}

// Paths are raw bytes. A catalog path, a skipped path or an inconsistent one
// that is not valid UTF-8 keeps every byte through JSON.
func TestRawPathsSurviveJSON(t *testing.T) {
	raw := "dir/caf\xe9\xff"
	c := Catalog{Version: 1, EpochID: "e202610-3fa94c1d", RunID: strings.Repeat("a", 32), Complete: true,
		Entries: []CatalogEntry{{Path: raw, Event: EventPresent, Type: "f"}, {Path: "plain", Event: EventPresent, Type: "d"}}}
	b, err := Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"path_b64"`) || !strings.Contains(string(b), `"path":"plain"`) {
		t.Fatalf("catalog JSON %s", b)
	}
	var back Catalog
	if err := Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Entries[0].Path != raw || back.Entries[1].Path != "plain" {
		t.Fatalf("catalog paths %q %q", back.Entries[0].Path, back.Entries[1].Path)
	}
	s := Snapshot{Skipped: []Skipped{{Path: raw, Reason: "fifo"}}, Inconsistent: []RawPath{RawPath(raw), "ok.log"}}
	b, _ = Marshal(s)
	var sb Snapshot
	if err := Unmarshal(b, &sb); err != nil {
		t.Fatal(err)
	}
	if sb.Skipped[0].Path != raw || string(sb.Inconsistent[0]) != raw || sb.Inconsistent[1] != "ok.log" {
		t.Fatalf("snapshot paths %+v %+v", sb.Skipped, sb.Inconsistent)
	}
}
