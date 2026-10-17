package wal

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/crypto"
)

// RestoreOptions are one point-in-time restore.
type RestoreOptions struct {
	// Target is the moment to replay to. With TargetName set it only picks
	// the base backup: the newest one that ended before it. With neither,
	// the replay runs to the end of the archive and the newest base is used.
	Target time.Time
	// TargetName is a restore point to replay to.
	TargetName string
	PGData     string
	// FetchCommand is restore_command, with %f and %p for PostgreSQL to
	// fill in.
	FetchCommand string
}

// RestoreResult is what a restore wrote.
type RestoreResult struct {
	Base BaseInfo
	// ArchiveEnd is when the newest WAL file in the archive was pushed.
	ArchiveEnd time.Time
	// NoConf is a base with no postgresql.conf in it: the cluster kept its
	// configuration outside the data directory, as Debian and Ubuntu do.
	NoConf bool
}

// Restore unpacks the newest complete base backup that ends before the
// target into an empty directory and sets PostgreSQL up to replay the
// archive to the target and promote. Starting PostgreSQL does the replay.
func (a *Archive) Restore(ctx context.Context, o RestoreOptions) (RestoreResult, error) {
	var res RestoreResult
	bases, _, err := a.Bases(ctx)
	if err != nil {
		return res, err
	}
	if len(bases) == 0 {
		return res, fmt.Errorf("the archive at %s holds no complete base backup. Take one with 'safegrd wal base'", a.Describe())
	}
	var pick *BaseInfo
	for i := range bases {
		if o.Target.IsZero() || bases[i].EndedAt.Before(o.Target) {
			pick = &bases[i]
		}
	}
	if pick == nil {
		return res, fmt.Errorf("no base backup ends before %s; the oldest ends at %s", stamp(o.Target), stamp(bases[0].EndedAt))
	}
	have, err := a.archivedNames(ctx)
	if err != nil {
		return res, err
	}
	for _, t := range have {
		if t.After(res.ArchiveEnd) {
			res.ArchiveEnd = t
		}
	}
	// Push times are whole seconds; a target within the last push's second
	// is still inside the archive.
	if o.TargetName == "" && !o.Target.IsZero() && o.Target.After(res.ArchiveEnd.Add(time.Second)) {
		return res, fmt.Errorf("the archive reaches %s, and %s is after it: the WAL since then is not archived yet. Restore to a time before it", stamp(res.ArchiveEnd), stamp(o.Target))
	}
	if err := emptyDir(o.PGData); err != nil {
		return res, err
	}
	if err := a.unpackBase(ctx, *pick, o.PGData); err != nil {
		return res, err
	}
	if err := writeRecovery(o.PGData, o.FetchCommand, o); err != nil {
		return res, err
	}
	res.Base = *pick
	if _, err := os.Stat(filepath.Join(o.PGData, "postgresql.conf")); errors.Is(err, os.ErrNotExist) {
		res.NoConf = true
	}
	return res, nil
}

func stamp(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05 UTC") }

// emptyDir makes dir, or accepts it when it exists and holds nothing.
func emptyDir(dir string) error {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return os.MkdirAll(dir, 0o700)
	}
	if err != nil {
		return err
	}
	if len(ents) > 0 {
		return fmt.Errorf("%s is not empty; a restore writes a whole data directory and needs an empty one", dir)
	}
	return os.Chmod(dir, 0o700)
}

func (a *Archive) unpackBase(ctx context.Context, b BaseInfo, dir string) error {
	rc, err := a.Store.Get(ctx, a.baseKey(b.BaseID, "base.tar.zst.age"))
	if err != nil {
		return fmt.Errorf("reading base %s: %w", b.BaseID, err)
	}
	defer rc.Close()
	pr, pw := io.Pipe()
	type decrypted struct {
		m   *crypto.StreamMetrics
		err error
	}
	done := make(chan decrypted, 1)
	go func() {
		m, err := crypto.DecryptStream(rc, pw, a.Identity)
		pw.CloseWithError(err)
		done <- decrypted{m, err}
	}()
	untarErr := untar(pr, dir)
	if untarErr == nil {
		_, untarErr = io.Copy(io.Discard, pr) // the tar's trailing blocks
	}
	pr.CloseWithError(io.ErrClosedPipe)
	d := <-done
	if d.err != nil {
		return fmt.Errorf("decrypting base %s: %w", b.BaseID, d.err)
	}
	if untarErr != nil {
		return fmt.Errorf("unpacking base %s: %w", b.BaseID, untarErr)
	}
	if d.m.RawSha256 != b.TarSha256 {
		return fmt.Errorf("base %s decrypts to other bytes than were written (%s, wrote %s)", b.BaseID, d.m.RawSha256[:16], b.TarSha256[:16])
	}
	return nil
}

func untar(r io.Reader, dir string) error {
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		name := path.Clean(strings.TrimPrefix(h.Name, "./"))
		if name == "." {
			continue
		}
		if path.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") {
			return fmt.Errorf("the base holds %q, outside the data directory", h.Name)
		}
		dst := filepath.Join(dir, filepath.FromSlash(name))
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dst, 0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
				return err
			}
			f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(h.Mode)&0o700|0o600)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
		case tar.TypeSymlink:
			// pg_basebackup -Ft writes pg_wal as a directory and refuses
			// tablespaces on stdout, so a link here is not PostgreSQL's.
			return fmt.Errorf("the base holds a symbolic link %q; pg_basebackup writes none into a tar on stdout, so this is not one of its backups", h.Name)
		default:
			return fmt.Errorf("the base holds %q of tar type %q", h.Name, h.Typeflag)
		}
	}
}

// writeRecovery sets the unpacked cluster up to replay the archive to the
// target and promote. Archiving is turned off on it: a restored cluster
// that archived would push a new timeline into the archive it came from.
func writeRecovery(dir, fetch string, o RestoreOptions) error {
	if err := os.WriteFile(filepath.Join(dir, "recovery.signal"), nil, 0o600); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, "postgresql.auto.conf"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	target := ""
	switch {
	case o.TargetName != "":
		target = "recovery_target_name = " + confQuote(o.TargetName) + "\n"
	case !o.Target.IsZero():
		target = "recovery_target_time = " + confQuote(o.Target.UTC().Format("2006-01-02 15:04:05.999999")+"+00") + "\n"
	}
	_, err = fmt.Fprintf(f, "\n# Written by safegrd wal restore\nrestore_command = %s\n%srecovery_target_action = 'promote'\narchive_mode = 'off'\n",
		confQuote(fetch), target)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// confQuote quotes a value for postgresql.conf.
func confQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
