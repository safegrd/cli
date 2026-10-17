package dump

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"io"

	"github.com/safegrd/cli/pkg/model"
)

// An archive writes its manifest last, after every table's rows, so a
// restore of chosen tables reads it twice: once for the manifest and the
// schema sections, to check or create each table before anything loads, and
// once for the rows.

// ArchiveSchema is what the first read keeps: the manifest and the schema
// sections by entry name (pre-data.sql, post-data.sql, sequences.sql).
type ArchiveSchema struct {
	Manifest *model.SnapshotMetadata
	Sections map[string]string
}

// ReadArchiveSchema reads a PostgreSQL archive's manifest and schema
// sections and reads past every table's rows.
func ReadArchiveSchema(src io.Reader) (*ArchiveSchema, error) {
	out := &ArchiveSchema{Sections: map[string]string{}}
	streams := &tableStreams{
		consume: func(_, _ string, rd io.Reader) error {
			_, err := io.Copy(io.Discard, rd)
			return err
		},
		other: func(hdr *tar.Header, rd io.Reader) error {
			switch hdr.Name {
			case entryManifest:
				var m model.SnapshotMetadata
				if err := json.NewDecoder(rd).Decode(&m); err != nil {
					return fmt.Errorf("the archive's manifest is unreadable: %w", err)
				}
				out.Manifest = &m
			case entryPreData, entryPostData, entrySequences:
				b, err := io.ReadAll(rd)
				if err != nil {
					return err
				}
				out.Sections[hdr.Name] = string(b)
			}
			return nil
		},
	}
	if err := streams.Run(tar.NewReader(src)); err != nil {
		return nil, err
	}
	if out.Manifest == nil {
		return nil, fmt.Errorf("the archive holds no manifest.json")
	}
	if _, ok := out.Sections[entryPreData]; !ok {
		return nil, fmt.Errorf("the archive holds no %s; restore the whole snapshot into an empty database", entryPreData)
	}
	return out, nil
}

// LoadArchiveTables passes the rows of each table in want ("schema.table")
// to load as one binary COPY stream, and reads past the rest.
func LoadArchiveTables(src io.Reader, want map[string]bool, load func(schema, table string, rows io.Reader) error) error {
	streams := &tableStreams{
		consume: func(schema, table string, rd io.Reader) error {
			if !want[schema+"."+table] {
				_, err := io.Copy(io.Discard, rd)
				return err
			}
			return load(schema, table, rd)
		},
		other: func(_ *tar.Header, rd io.Reader) error {
			_, err := io.Copy(io.Discard, rd)
			return err
		},
	}
	return streams.Run(tar.NewReader(src))
}
