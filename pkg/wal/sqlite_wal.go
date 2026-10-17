package wal

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

// SQLite in WAL mode appends each changed page to <db>-wal as a frame: a
// 24-byte header (page number, the database's size in pages when the frame
// commits a transaction, the WAL's two salts and a running checksum) and the
// page. The file starts with a 32-byte header whose salts every valid frame
// repeats. A checkpoint copies frames into the database; the next writer then
// restarts the WAL at its start with the first salt one higher. Frames past
// the last one whose salts and checksum hold are left over from before a
// restart, and are not part of the log.

const (
	sqliteWALHeader = 32
	sqliteFrameHead = 24
)

// SQLiteWALHeader is the WAL file's header.
type SQLiteWALHeader struct {
	BigEndianSum  bool
	PageSize      uint32
	CheckpointSeq uint32
	Salt1, Salt2  uint32
	Sum1, Sum2    uint32
}

// FrameSize is the size of one frame.
func (h SQLiteWALHeader) FrameSize() int64 { return sqliteFrameHead + int64(h.PageSize) }

// ReadSQLiteWALHeader reads a WAL file's header. A missing or empty file has
// none, which is io.EOF.
func ReadSQLiteWALHeader(path string) (SQLiteWALHeader, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return SQLiteWALHeader{}, io.EOF
	}
	if err != nil {
		return SQLiteWALHeader{}, err
	}
	defer f.Close()
	b := make([]byte, sqliteWALHeader)
	if _, err := io.ReadFull(f, b); err != nil {
		if err == io.ErrUnexpectedEOF {
			return SQLiteWALHeader{}, io.EOF
		}
		return SQLiteWALHeader{}, err
	}
	return parseSQLiteWALHeader(b)
}

func parseSQLiteWALHeader(b []byte) (SQLiteWALHeader, error) {
	var h SQLiteWALHeader
	magic := binary.BigEndian.Uint32(b[0:4])
	if magic != 0x377f0682 && magic != 0x377f0683 {
		return h, fmt.Errorf("not a SQLite WAL file (magic %08x)", magic)
	}
	h.BigEndianSum = magic&1 == 1
	h.PageSize = binary.BigEndian.Uint32(b[8:12])
	if h.PageSize < 512 || h.PageSize > 65536 || h.PageSize&(h.PageSize-1) != 0 {
		return h, fmt.Errorf("the WAL header gives a page size of %d", h.PageSize)
	}
	h.CheckpointSeq = binary.BigEndian.Uint32(b[12:16])
	h.Salt1, h.Salt2 = binary.BigEndian.Uint32(b[16:20]), binary.BigEndian.Uint32(b[20:24])
	h.Sum1, h.Sum2 = binary.BigEndian.Uint32(b[24:28]), binary.BigEndian.Uint32(b[28:32])
	s1, s2 := sqliteWALSum(h.BigEndianSum, 0, 0, b[:24])
	if s1 != h.Sum1 || s2 != h.Sum2 {
		return h, errors.New("the WAL header's checksum does not hold")
	}
	return h, nil
}

// sqliteWALSum continues SQLite's WAL checksum over b, whose length is a
// multiple of 8.
func sqliteWALSum(bigEndian bool, s1, s2 uint32, b []byte) (uint32, uint32) {
	order := binary.ByteOrder(binary.LittleEndian)
	if bigEndian {
		order = binary.BigEndian
	}
	for i := 0; i+8 <= len(b); i += 8 {
		s1 += order.Uint32(b[i:]) + s2
		s2 += order.Uint32(b[i+4:]) + s1
	}
	return s1, s2
}

// WALCursor is how far into one WAL (one run of the header's salts) the
// frames have been read: the offset after the last frame taken and the
// running checksum there.
type WALCursor struct {
	Header     SQLiteWALHeader
	Offset     int64
	Sum1, Sum2 uint32
}

// StartCursor is a cursor at the first frame of the WAL with header h.
func StartCursor(h SQLiteWALHeader) WALCursor {
	return WALCursor{Header: h, Offset: sqliteWALHeader, Sum1: h.Sum1, Sum2: h.Sum2}
}

// ReadCommitted reads the frames after c up to the last one that commits a
// transaction, and returns them as they are in the file, with the cursor
// after them. Frames of a transaction still being written are left for the
// next read.
func ReadCommitted(path string, c WALCursor) ([]byte, WALCursor, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, c, err
	}
	defer f.Close()
	if _, err := f.Seek(c.Offset, io.SeekStart); err != nil {
		return nil, c, err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, c, err
	}
	fs := c.Header.FrameSize()
	s1, s2 := c.Sum1, c.Sum2
	end, endS1, endS2 := int64(0), s1, s2
	for off := int64(0); off+fs <= int64(len(data)); off += fs {
		fr := data[off : off+fs]
		if binary.BigEndian.Uint32(fr[8:12]) != c.Header.Salt1 || binary.BigEndian.Uint32(fr[12:16]) != c.Header.Salt2 {
			break
		}
		s1, s2 = sqliteWALSum(c.Header.BigEndianSum, s1, s2, fr[:8])
		s1, s2 = sqliteWALSum(c.Header.BigEndianSum, s1, s2, fr[sqliteFrameHead:])
		if s1 != binary.BigEndian.Uint32(fr[16:20]) || s2 != binary.BigEndian.Uint32(fr[20:24]) {
			break
		}
		if binary.BigEndian.Uint32(fr[4:8]) != 0 {
			end, endS1, endS2 = off+fs, s1, s2
		}
	}
	next := c
	next.Offset, next.Sum1, next.Sum2 = c.Offset+end, endS1, endS2
	return data[:end], next, nil
}

// applyFrames writes the pages of whole transactions in frames into the
// database file f, in order, and returns the database's size in pages after
// the last commit, or 0 when frames held none.
func applyFrames(f *os.File, frames []byte, pageSize uint32) (uint32, error) {
	fs := int(sqliteFrameHead + pageSize)
	if len(frames)%fs != 0 {
		return 0, fmt.Errorf("%d bytes of WAL frames are not a whole number of %d-byte frames", len(frames), fs)
	}
	var size uint32
	for off := 0; off < len(frames); off += fs {
		fr := frames[off : off+fs]
		pgno := binary.BigEndian.Uint32(fr[0:4])
		if pgno == 0 {
			return 0, errors.New("a WAL frame names page 0")
		}
		if _, err := f.WriteAt(fr[sqliteFrameHead:], int64(pgno-1)*int64(pageSize)); err != nil {
			return 0, err
		}
		if commit := binary.BigEndian.Uint32(fr[4:8]); commit != 0 {
			size = commit
		}
	}
	return size, nil
}
