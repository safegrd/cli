package wal

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"
)

func fakeControl(t *testing.T, version uint32, crcAt int) string {
	t.Helper()
	dir := t.TempDir()
	buf := make([]byte, 8192)
	binary.LittleEndian.PutUint64(buf[0:], 7123456789012345678)
	binary.LittleEndian.PutUint32(buf[8:], version)
	binary.LittleEndian.PutUint64(buf[32:], 0x1_6B374D848)
	for i := 40; i < crcAt; i++ {
		buf[i] = byte(i * 7)
	}
	binary.LittleEndian.PutUint32(buf[crcAt:], crc32.Checksum(buf[:crcAt], castagnoli))
	if err := os.MkdirAll(filepath.Join(dir, "global"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "global", "pg_control"), buf, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestInvalidateCheckpointClearsItAndKeepsTheCRCValid(t *testing.T) {
	dir := fakeControl(t, 1300, 296)
	if err := InvalidateCheckpoint(dir); err != nil {
		t.Fatal(err)
	}
	buf, _ := os.ReadFile(filepath.Join(dir, "global", "pg_control"))
	if binary.LittleEndian.Uint64(buf[32:]) != invalidLocation {
		t.Error("the checkpoint is not the invalid location")
	}
	if at, ok := controlCRCAt(buf); !ok || at != 296 {
		t.Errorf("the CRC does not check at 296 after the change: %d %v", at, ok)
	}
	if err := InvalidateCheckpoint(fakeControl(t, 1800, 300)); !errors.Is(err, ErrControlUnknown) {
		t.Errorf("an unknown pg_control_version: %v", err)
	}
}
