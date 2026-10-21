package wal

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
)

// A data directory restored from a base backup has to start from the
// checkpoint its backup_label names. Without the label PostgreSQL starts
// from the checkpoint pg_control records, which was taken before or during
// the copy: it replays from the wrong place and comes up looking healthy
// over files copied at different moments. A restore therefore clears the
// checkpoint location in pg_control and rewrites its CRC, as pgBackRest
// does. With backup_label in place PostgreSQL reads the checkpoint from the
// label and starts; without it, it finds no valid checkpoint and refuses.
//
// The location is not zeroed: PostgreSQL refuses a zero at once, label or
// not ("control file contains invalid checkpoint location"). It is set to
// invalidLocation, a well-formed position in WAL segment 0, which initdb
// never writes, so no checkpoint record is ever found there.

// The layout of the start of ControlFileData, the same from PostgreSQL 13
// to 17: system_identifier (8 bytes), pg_control_version (4),
// catalog_version_no (4), state (4, then 4 of padding), time (8), and
// checkPoint (8), the field cleared here.
const (
	controlVersionAt  = 8
	controlCheckpoint = 32
	// invalidLocation is 0/2028: past a page header on the second page of
	// segment 0.
	invalidLocation = 8192 + 40
)

// controlVersions are the pg_control_version values of PostgreSQL 13 to 16
// (1300) and 17 (1700): the layouts this reads.
var controlVersions = map[uint32]string{1300: "PostgreSQL 13 to 16", 1700: "PostgreSQL 17"}

// ErrControlUnknown is a pg_control of a layout this version does not read.
var ErrControlUnknown = errors.New("pg_control is of a PostgreSQL version this safegrd does not read")

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// controlCRCAt finds the CRC field: the first 4-byte-aligned offset whose
// four bytes are the CRC-32C of everything before them. The CRC is the last
// field of ControlFileData, so the first match is it; anything else would
// need four bytes of the struct to equal the CRC of what precedes them.
func controlCRCAt(buf []byte) (int, bool) {
	for off := controlCheckpoint + 8; off+4 <= len(buf) && off <= 1024; off += 4 {
		if crc32.Checksum(buf[:off], castagnoli) == binary.LittleEndian.Uint32(buf[off:]) {
			return off, true
		}
	}
	return 0, false
}

// InvalidateCheckpoint clears the checkpoint location in pgdata's
// pg_control and rewrites its CRC, so the cluster starts only from its
// backup_label.
func InvalidateCheckpoint(pgdata string) error {
	p := filepath.Join(pgdata, "global", "pg_control")
	buf, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	if len(buf) < 512 {
		return fmt.Errorf("%s is %d bytes; pg_control is 8192", p, len(buf))
	}
	v := binary.LittleEndian.Uint32(buf[controlVersionAt:])
	if _, ok := controlVersions[v]; !ok {
		return fmt.Errorf("%w (pg_control_version %d)", ErrControlUnknown, v)
	}
	at, ok := controlCRCAt(buf)
	if !ok {
		return fmt.Errorf("%s: its CRC does not check, so it is not changed", p)
	}
	binary.LittleEndian.PutUint64(buf[controlCheckpoint:], invalidLocation)
	binary.LittleEndian.PutUint32(buf[at:], crc32.Checksum(buf[:at], castagnoli))
	tmp := p + ".safegrd"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(buf); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, p)
}
