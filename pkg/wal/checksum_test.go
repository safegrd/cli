package wal

import "testing"

func TestChecksumFailuresAreCountedByFile(t *testing.T) {
	stderr := `WARNING:  checksum verification failed in file "./base/5/16384", block 0: calculated 9A6B but expected 5C3D
WARNING:  checksum verification failed in file "./base/5/16384", block 3: calculated 1111 but expected 2222
WARNING:  further checksum verification failures in file "./base/5/16384" will not be reported
WARNING:  file "./base/5/16384" has a total of 7 checksum verification failures
WARNING:  checksum verification failed in file "./base/5/16390", block 1: calculated 1 but expected 2
WARNING:  file "./base/5/16390" has a total of 1 checksum verification failure
pg_basebackup: error: checksum error occurred
`
	by, ok := checksumFailures(stderr)
	if !ok || by["base/5/16384"] != 7 || by["base/5/16390"] != 1 || len(by) != 2 {
		t.Fatalf("got %v %v", by, ok)
	}
	if got := checksumWords(by); got != "8 pages in base/5/16384 (7), base/5/16390 (1)" {
		t.Fatalf("words: %q", got)
	}
	if _, ok := checksumFailures("pg_basebackup: error: could not connect"); ok {
		t.Fatal("a connection failure read as checksum failures")
	}
}
