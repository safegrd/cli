package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/safegrd/cli/pkg/crypto"
	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/storage"
)

// restoreArchiveTables is --table on an archive (format: tar). The archive
// writes its manifest after the rows, so it is read twice: first for the
// manifest and the schema sections, to check or create each table, then for
// the chosen tables' rows. Each read is held to the snapshot's digest, and
// the second one before the transaction commits.
func restoreArchiveTables(ctx context.Context, provider storage.StorageProvider, meta *model.SnapshotMetadata, id, key, targetURL string, tables []string) error {
	if meta != nil && meta.SurfaceType != "" && meta.SurfaceType != model.SurfaceTypePostgres {
		return fmt.Errorf("--table restores tables of a PostgreSQL snapshot; %s is a %s snapshot and restores whole", id, meta.SurfaceType)
	}
	if targetURL == "" || dump.SurfaceTypeOfURL(targetURL) != model.SurfaceTypePostgres {
		return fmt.Errorf("--table restores into a PostgreSQL database: pass --target postgres://…")
	}
	fmt.Printf("Restoring %s from %s into %s\n", strings.Join(tables, ", "), id, dump.RedactURL(targetURL))

	var schema *dump.ArchiveSchema
	if err := readArchive(ctx, provider, meta, id, key, func(r io.Reader) error {
		var err error
		schema, err = dump.ReadArchiveSchema(r)
		return err
	}, nil); err != nil {
		return err
	}
	listed := map[string]bool{}
	for _, t := range schema.Manifest.TableStats {
		listed["data/"+t.Schema+"/"+t.TableName+".copy"] = true
	}
	asOf := schema.Manifest.CreatedAt
	if meta != nil && !meta.CreatedAt.IsZero() {
		asOf = meta.CreatedAt
	}
	tr := &tableRestore{id: id, asOf: asOf, sections: func() (map[string]string, error) { return schema.Sections, nil }}
	if err := tr.pick(schema.Manifest.TableStats, tables, func(p string) bool { return listed[p] }); err != nil {
		return err
	}
	tx, done, err := tr.begin(ctx, targetURL)
	if err != nil {
		return err
	}
	defer done()
	if err := tr.prepare(ctx, tx); err != nil {
		return err
	}
	byName := map[string]tablePick{}
	want := map[string]bool{}
	for _, p := range tr.picks {
		byName[p.name], want[p.name] = p, true
	}
	loaded := map[string]bool{}
	err = readArchive(ctx, provider, meta, id, key, func(r io.Reader) error {
		return dump.LoadArchiveTables(r, want, func(s, t string, rows io.Reader) error {
			p := byName[s+"."+t]
			loaded[p.name] = true
			return tr.load(ctx, tx, p, rows)
		})
	}, func() error {
		for _, p := range tr.picks {
			if !loaded[p.name] {
				return fmt.Errorf("snapshot %s holds no rows for %s; nothing was restored", id, p.name)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return tr.commit(ctx, tx)
}

// readArchive downloads and decrypts the snapshot, passes the plaintext to
// read, reads the rest so the digest covers the whole stream, then runs
// before (if set) and checks the digest. A failure of any is the error.
func readArchive(ctx context.Context, provider storage.StorageProvider, meta *model.SnapshotMetadata, id, key string, read func(io.Reader) error, before func() error) error {
	cipher, err := provider.DownloadSnapshot(ctx, id)
	if err != nil {
		return fmt.Errorf("failed downloading snapshot from storage: %w", err)
	}
	defer cipher.Close()
	pr, pw := io.Pipe()
	defer pr.Close()
	type result struct {
		m   *crypto.StreamMetrics
		err error
	}
	dec := make(chan result, 1)
	go func() {
		m, err := crypto.DecryptStream(cipher, pw, key)
		_ = pw.CloseWithError(err)
		dec <- result{m, err}
	}()
	if err := read(pr); err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, pr) // the rest of the stream, for the digest
	res := <-dec
	if res.err != nil {
		return fmt.Errorf("stream decryption error (tampered snapshot or invalid key): %w", res.err)
	}
	if before != nil {
		if err := before(); err != nil {
			return err
		}
	}
	return checkRestoreDigest(ctx, meta, id, res.m)
}
