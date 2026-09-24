package fastcdc

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

func TestFastCDCReconstructionAndBounds(t *testing.T) {
	data := make([]byte, 500*1024) // 500 KB
	_, _ = rand.Read(data)

	minSize := 4 * 1024
	avgSize := 16 * 1024
	maxSize := 64 * 1024

	chunker := NewChunker(bytes.NewReader(data), minSize, avgSize, maxSize)

	var reconstructed []byte
	var chunks []*Chunk

	for {
		chunk, err := chunker.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("unexpected chunker error: %v", err)
		}
		chunks = append(chunks, chunk)
		reconstructed = append(reconstructed, chunk.Data...)

		if chunk.Length < minSize && len(reconstructed) < len(data) {
			t.Fatalf("chunk length %d is below minSize %d", chunk.Length, minSize)
		}
		if chunk.Length > maxSize {
			t.Fatalf("chunk length %d exceeds maxSize %d", chunk.Length, maxSize)
		}
	}

	if !bytes.Equal(data, reconstructed) {
		t.Fatalf("reconstructed data does not match original data")
	}

	if len(chunks) < 5 {
		t.Fatalf("expected at least 5 chunks for 500KB with avg 16KB, got %d", len(chunks))
	}
}

func TestFastCDCDeduplicationShiftResistance(t *testing.T) {
	base := make([]byte, 200*1024)
	_, _ = rand.Read(base)

	prefix := []byte("PREPENDED DATA TO TEST CDC BOUNDARY PRESERVATION")
	modified := append(prefix, base...)

	minSize := 4 * 1024
	avgSize := 16 * 1024
	maxSize := 64 * 1024

	baseChunker := NewChunker(bytes.NewReader(base), minSize, avgSize, maxSize)
	baseIndex := NewChunkIndex()

	for {
		chunk, err := baseChunker.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("base chunk error: %v", err)
		}
		baseIndex.Put(chunk.Checksum, ChunkLocation{
			PackfileID: "pack-1",
			Offset:     chunk.Offset,
			Length:     chunk.Length,
		})
	}

	modChunker := NewChunker(bytes.NewReader(modified), minSize, avgSize, maxSize)
	matchingChunks := 0
	totalModChunks := 0

	for {
		chunk, err := modChunker.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("mod chunk error: %v", err)
		}
		totalModChunks++
		if baseIndex.Has(chunk.Checksum) {
			matchingChunks++
		}
	}

	if matchingChunks == 0 {
		t.Fatalf("FastCDC failed to identify duplicate chunks after shifting prefix: 0 of %d matched", totalModChunks)
	}
	if matchingChunks < totalModChunks-2 {
		t.Fatalf("expected at least %d matching chunks, got %d out of %d", totalModChunks-2, matchingChunks, totalModChunks)
	}
}

func TestPackfileWriterAndIndex(t *testing.T) {
	var buf bytes.Buffer
	pw, err := NewPackfileWriter(&buf)
	if err != nil {
		t.Fatalf("NewPackfileWriter error: %v", err)
	}

	index := NewChunkIndex()

	sampleData := []byte("SafeGrd WORM immutable chunk 1")
	chunk := &Chunk{
		Offset:   0,
		Length:   len(sampleData),
		Checksum: [32]byte{1, 2, 3},
		Data:     sampleData,
	}

	offset, err := pw.AppendChunk(chunk)
	if err != nil {
		t.Fatalf("AppendChunk error: %v", err)
	}

	index.Put(chunk.Checksum, ChunkLocation{
		PackfileID: "pack-001",
		Offset:     offset,
		Length:     chunk.Length,
	})

	if !index.Has(chunk.Checksum) {
		t.Fatalf("index missing added chunk")
	}

	loc, ok := index.Get(chunk.Checksum)
	if !ok || loc.PackfileID != "pack-001" || loc.Offset != offset {
		t.Fatalf("unexpected chunk location from index: %+v", loc)
	}
}
