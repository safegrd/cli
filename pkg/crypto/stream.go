package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"

	"filippo.io/age"
	"github.com/klauspost/compress/zstd"
)

// StreamMetrics captures size and cryptographic checksums for a stream operation.
type StreamMetrics struct {
	RawBytes         int64   `json:"raw_bytes"`
	EncryptedBytes   int64   `json:"encrypted_bytes"`
	RawSha256        string  `json:"raw_sha256"`
	EncryptedSha256  string  `json:"encrypted_sha256"`
	CompressionRatio float64 `json:"compression_ratio"`
}

// countingWriter wraps an io.Writer while computing SHA-256 and counting bytes.
type countingWriter struct {
	writer io.Writer
	hasher hash.Hash
	count  int64
}

func newCountingWriter(w io.Writer) *countingWriter {
	return &countingWriter{
		writer: w,
		hasher: sha256.New(),
	}
}

func (cw *countingWriter) Write(p []byte) (int, error) {
	n, err := cw.writer.Write(p)
	if n > 0 {
		cw.count += int64(n)
		cw.hasher.Write(p[:n])
	}
	return n, err
}

func (cw *countingWriter) SumHex() string {
	return hex.EncodeToString(cw.hasher.Sum(nil))
}

// countingReader wraps an io.Reader while computing SHA-256 and counting bytes.
type countingReader struct {
	reader io.Reader
	hasher hash.Hash
	count  int64
}

func newCountingReader(r io.Reader) *countingReader {
	return &countingReader{
		reader: r,
		hasher: sha256.New(),
	}
}

func (cr *countingReader) Read(p []byte) (int, error) {
	n, err := cr.reader.Read(p)
	if n > 0 {
		cr.count += int64(n)
		cr.hasher.Write(p[:n])
	}
	return n, err
}

func (cr *countingReader) SumHex() string {
	return hex.EncodeToString(cr.hasher.Sum(nil))
}

// EncryptStream streams plaintext from src, compresses with zstd, encrypts with Age,
// and writes ciphertext to dst. No unencrypted data is written to disk.
func EncryptStream(src io.Reader, dst io.Writer, publicKey string) (*StreamMetrics, error) {
	recipient, err := ParseRecipient(publicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient key: %w", err)
	}

	// Ciphertext destination wrapper (counts encrypted bytes & computes encrypted sha256)
	cipherCountingWriter := newCountingWriter(dst)

	// Age encryption writer targeting cipherCountingWriter
	ageWriter, err := age.Encrypt(cipherCountingWriter, recipient)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize age encryption: %w", err)
	}

	// zstd compression writer targeting ageWriter
	zstdWriter, err := zstd.NewWriter(ageWriter, zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		ageWriter.Close()
		return nil, fmt.Errorf("failed to initialize zstd compressor: %w", err)
	}

	// Raw source wrapper (counts raw bytes & computes raw sha256)
	rawCountingReader := newCountingReader(src)

	// Stream copy from raw reader to zstd writer
	buf := make([]byte, 64*1024)
	if _, err := io.CopyBuffer(zstdWriter, rawCountingReader, buf); err != nil {
		zstdWriter.Close()
		ageWriter.Close()
		return nil, fmt.Errorf("streaming encryption pipeline error: %w", err)
	}

	// Ensure all zstd blocks and age envelopes are cleanly flushed & closed
	if err := zstdWriter.Close(); err != nil {
		ageWriter.Close()
		return nil, fmt.Errorf("failed to finalize compression: %w", err)
	}
	if err := ageWriter.Close(); err != nil {
		return nil, fmt.Errorf("failed to finalize encryption envelope: %w", err)
	}

	var ratio float64
	if cipherCountingWriter.count > 0 {
		ratio = float64(rawCountingReader.count) / float64(cipherCountingWriter.count)
	}

	return &StreamMetrics{
		RawBytes:         rawCountingReader.count,
		EncryptedBytes:   cipherCountingWriter.count,
		RawSha256:        rawCountingReader.SumHex(),
		EncryptedSha256:  cipherCountingWriter.SumHex(),
		CompressionRatio: ratio,
	}, nil
}

// DecryptStream streams ciphertext from src, decrypts with Age, decompresses with zstd,
// and writes plaintext to dst.
func DecryptStream(src io.Reader, dst io.Writer, privateKey string) (*StreamMetrics, error) {
	identity, err := ParseIdentity(privateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid identity key: %w", err)
	}

	// Count encrypted bytes and hash ciphertext
	cipherCountingReader := newCountingReader(src)

	// Age decryption reader
	ageReader, err := age.Decrypt(cipherCountingReader, identity)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize age decryptor (bad key or corrupt stream): %w", err)
	}

	// zstd decompression reader
	zstdReader, err := zstd.NewReader(ageReader)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize zstd decompressor: %w", err)
	}
	defer zstdReader.Close()

	// Count raw bytes and hash plaintext
	rawCountingWriter := newCountingWriter(dst)

	buf := make([]byte, 64*1024)
	if _, err := io.CopyBuffer(rawCountingWriter, zstdReader, buf); err != nil {
		return nil, fmt.Errorf("streaming decryption pipeline error: %w", err)
	}

	var ratio float64
	if cipherCountingReader.count > 0 {
		ratio = float64(rawCountingWriter.count) / float64(cipherCountingReader.count)
	}

	return &StreamMetrics{
		RawBytes:         rawCountingWriter.count,
		EncryptedBytes:   cipherCountingReader.count,
		RawSha256:        rawCountingWriter.SumHex(),
		EncryptedSha256:  cipherCountingReader.SumHex(),
		CompressionRatio: ratio,
	}, nil
}
