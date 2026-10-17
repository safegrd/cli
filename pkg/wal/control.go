package wal

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ReadSystemID reads the cluster's system identifier from global/pg_control
// under pgdata. It is the first field of the file, in the machine's byte
// order; every platform PostgreSQL and this CLI both run on is
// little-endian.
func ReadSystemID(pgdata string) (string, error) {
	p := filepath.Join(pgdata, "global", "pg_control")
	f, err := os.Open(p)
	if err != nil {
		return "", fmt.Errorf("reading the system identifier: %w. Run this from the data directory, as archive_command does, or pass --pgdata", err)
	}
	defer f.Close()
	var head [12]byte
	if _, err := io.ReadFull(f, head[:]); err != nil {
		return "", fmt.Errorf("%s: %w", p, err)
	}
	return systemIDFromControl(head[:], p)
}

func systemIDFromControl(head []byte, where string) (string, error) {
	id := binary.LittleEndian.Uint64(head[0:8])
	version := binary.LittleEndian.Uint32(head[8:12])
	// pg_control_version is 1300 from PostgreSQL 13 on; anything far off is
	// a big-endian file or not pg_control at all.
	if id == 0 || version < 1000 || version > 9999 {
		return "", fmt.Errorf("%s does not read as pg_control (system identifier %d, version %d)", where, id, version)
	}
	return strconv.FormatUint(id, 10), nil
}

// LSN is a position in the WAL.
type LSN uint64

// ParseLSN reads "16/B374D848".
func ParseLSN(s string) (LSN, error) {
	hi, lo, ok := strings.Cut(strings.TrimSpace(s), "/")
	if !ok {
		return 0, fmt.Errorf("%q is not an LSN", s)
	}
	h, err1 := strconv.ParseUint(hi, 16, 32)
	l, err2 := strconv.ParseUint(lo, 16, 32)
	if err1 != nil || err2 != nil {
		return 0, fmt.Errorf("%q is not an LSN", s)
	}
	return LSN(h<<32 | l), nil
}

func (l LSN) String() string { return fmt.Sprintf("%X/%X", uint64(l)>>32, uint32(l)) }

// SegmentName is the WAL file holding lsn on timeline tli.
func SegmentName(tli uint32, lsn LSN, segSize uint64) string {
	return segName(tli, uint64(lsn)/segSize, segSize)
}

func segName(tli uint32, segno, segSize uint64) string {
	per := uint64(0x100000000) / segSize
	return fmt.Sprintf("%08X%08X%08X", tli, segno/per, segno%per)
}

// parseSegName reads a segment's timeline and number back.
func parseSegName(name string, segSize uint64) (tli uint32, segno uint64, err error) {
	if !IsSegment(name) {
		return 0, 0, fmt.Errorf("%q is not a segment", name)
	}
	t, _ := strconv.ParseUint(name[0:8], 16, 32)
	hi, _ := strconv.ParseUint(name[8:16], 16, 32)
	lo, _ := strconv.ParseUint(name[16:24], 16, 32)
	per := uint64(0x100000000) / segSize
	return uint32(t), hi*per + lo, nil
}

// ParseSegmentSize reads SHOW wal_segment_size ("16MB", "1GB").
func ParseSegmentSize(s string) (uint64, error) {
	given := strings.TrimSpace(s)
	num, mult := given, uint64(1)
	for suffix, m := range map[string]uint64{"kB": 1 << 10, "MB": 1 << 20, "GB": 1 << 30} {
		if strings.HasSuffix(given, suffix) {
			num, mult = strings.TrimSuffix(given, suffix), m
			break
		}
	}
	n, err := strconv.ParseUint(num, 10, 64)
	size := n * mult
	if err != nil || size < 1<<20 || size > 1<<30 || size&(size-1) != 0 {
		return 0, fmt.Errorf("wal_segment_size %q is not a power of two from 1MB to 1GB", given)
	}
	return size, nil
}
