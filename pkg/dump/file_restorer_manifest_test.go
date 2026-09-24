package dump

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/safegrd/cli/pkg/model"
)

// Each case takes a real archive from the collector and changes one thing in
// it that the counts, byte totals and per-file digests do not see. Every one of
// them passed verification before the entries were held to the sealed manifest.
// The manifest itself is left untouched, which is the point: the archive
// no longer matches what was sealed, and the drill has to say so.
func TestFileRestorer_EveryEntryIsHeldToTheSealedManifest(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks require privilege on Windows")
	}

	cases := []struct {
		name    string
		rewrite func(hdr *tar.Header, body []byte) (*tar.Header, []byte)
		want    string
	}{
		{
			name: "a symlink repointed",
			rewrite: func(hdr *tar.Header, body []byte) (*tar.Header, []byte) {
				if hdr.Typeflag == tar.TypeSymlink {
					hdr.Linkname = "/etc/shadow"
				}
				return hdr, body
			},
			want: `symlink nested/link.txt points at "/etc/shadow" in the archive but was sealed pointing at "../plain.txt"`,
		},
		{
			// Same size, same bytes, another name: the file count and the byte
			// volume are unchanged, and the digest map is keyed by the sealed
			// path, so the renamed file's digest was never looked up.
			name: "a file renamed",
			rewrite: func(hdr *tar.Header, body []byte) (*tar.Header, []byte) {
				if hdr.Name == "plain.txt" {
					hdr.Name = "plain.txy"
				}
				return hdr, body
			},
			want: "plain.txy is in the archive but not in the sealed manifest",
		},
		{
			name: "a regular file turned into a hard link",
			rewrite: func(hdr *tar.Header, body []byte) (*tar.Header, []byte) {
				if hdr.Name == "nested/leaf.md" {
					hdr.Typeflag = tar.TypeLink
					hdr.Linkname = "plain.txt"
					hdr.Size = 0
					return hdr, nil
				}
				return hdr, body
			},
			want: `nested/leaf.md has tar type "1"`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			archive, meta := collectSymlinkTree(t)
			tampered := rewriteTar(t, archive, tc.rewrite)

			res, err := NewFileRestorer().InspectFileArchive(context.Background(), bytes.NewReader(tampered), meta)
			if err != nil {
				t.Fatalf("InspectFileArchive: %v", err)
			}
			if res.Passed {
				t.Fatalf("an archive that no longer matches its sealed manifest verified")
			}
			var entries *model.AssertionResult
			for i, a := range res.Assertions {
				if a.Name == "Archive Entries Match Sealed Manifest" {
					entries = &res.Assertions[i]
				}
			}
			if entries == nil || entries.Passed {
				t.Fatalf("the entries assertion did not fail; assertions: %+v", res.Assertions)
			}
			if !strings.Contains(entries.Message, tc.want) {
				t.Errorf("the failure does not name the defect:\n  got  %s\n  want %s", entries.Message, tc.want)
			}
		})
	}

	// And the untouched archive still verifies, or the assertion is simply
	// failing everything.
	archive, meta := collectSymlinkTree(t)
	res, err := NewFileRestorer().InspectFileArchive(context.Background(), bytes.NewReader(archive), meta)
	if err != nil || !res.Passed {
		t.Fatalf("an untouched archive must verify: err=%v msg=%q", err, res.ErrorMessage)
	}
}

func collectSymlinkTree(t *testing.T) ([]byte, *model.SnapshotMetadata) {
	t.Helper()
	dir := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(dir, "plain.txt"), []byte("top level config"), 0o644))
	must(os.MkdirAll(filepath.Join(dir, "nested"), 0o755))
	must(os.WriteFile(filepath.Join(dir, "nested", "leaf.md"), []byte("nested payload"), 0o644))
	must(os.Symlink("../plain.txt", filepath.Join(dir, "nested", "link.txt")))

	reader, meta, err := NewFileCollector(FileCollectorConfig{RootDir: dir}).ScanAndStream(context.Background())
	must(err)
	archive, err := io.ReadAll(reader)
	must(err)
	return archive, meta
}

// rewriteTar copies an archive entry by entry through fn.
func rewriteTar(t *testing.T, archive []byte, fn func(*tar.Header, []byte) (*tar.Header, []byte)) []byte {
	t.Helper()
	tr := tar.NewReader(bytes.NewReader(archive))
	var out bytes.Buffer
	tw := tar.NewWriter(&out)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		hdr, body = fn(hdr, body)
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
