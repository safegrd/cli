package fastcdc

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

const (
	DefaultMinSize = 16 * 1024  // 16 KB
	DefaultAvgSize = 64 * 1024  // 64 KB
	DefaultMaxSize = 256 * 1024 // 256 KB

	PackfileMagic = "SGD_PACK\x01"
)

// GearTable is a 256-element uint64 array for Gear rolling hash.
var GearTable = [256]uint64{
	0x80549c4f74ab2e53, 0x1cfc150c44bc6b29, 0xc7c9fc7dfc5efd89, 0x7383bb370cb9e434,
	0xe49eb0f88e7a08b6, 0x1d5f303f271295b9, 0xc55c7017c66cb17c, 0x136bc75db93fcb65,
	0x16bfa0f4e24ef43d, 0x56a4ca2dfa64016f, 0x9fb96efee9d2475e, 0x77073b64dc4f3ff4,
	0x6166504a5e3860bb, 0x2287f654b9d0dc08, 0xef4f0e9f1a0e1c66, 0x6e288e17812f8646,
	0x8b3fa47d8ff278aa, 0x2213e4b77f805a54, 0x2e061d4a04ab4f16, 0x736932402ba6aa3e,
	0x68541be5e6cfcfb5, 0x759850e0eb867160, 0x3d0b2848c4146c87, 0x58b90b8f413346d0,
	0xbbca7a77e53f191b, 0xa5ff4cb22c070a6d, 0x7530666ba8529cb6, 0x6c9d5ef264a66a15,
	0x7c7ac88849b2c89b, 0x82f0fa3c15aa1f02, 0x8e82684ab1bca961, 0x48967f6735e5d3c8,
	0x2427a1b41c0ea4ee, 0xb1bca96135e5d3c8, 0xd0d5eeebcf7c3b28, 0x409559c5d0fef392,
	0xd342e4ecadcbcfdc, 0x8117a0cb5bfa22f1, 0x9cb927f67be56d78, 0x7a27be633d3c26dc,
	0x818610eb675079a4, 0x28054a3a60a74792, 0xb9e43480549c4f74, 0xab2e531cfc150c44,
	0xbc6b29c7c9fc7dfc, 0x5efd897383bb370c, 0xb9e434e49eb0f88e, 0x7a08b61d5f303f27,
	0x1295b9c55c7017c6, 0x6cb17c136bc75db9, 0x3fcb6516bfa0f4e2, 0x4ef43d56a4ca2dfa,
	0x64016f9fb96efee9, 0xd2475e77073b64dc, 0x4f3ff46166504a5e, 0x3860bb2287f654b9,
	0xd0dc08ef4f0e9f1a, 0x0e1c666e288e1781, 0x2f86468b3fa47d8f, 0xf278aa2213e4b77f,
	0x805a542e061d4a04, 0xab4f16736932402b, 0xa6aa3e68541be5e6, 0xcfcfb5759850e0eb,
	0x8671603d0b2848c4, 0x146c8758b90b8f41, 0x3346d0bbca7a77e5, 0x3f191ba5ff4cb22c,
	0x070a6d7530666ba8, 0x529cb66c9d5ef264, 0xa66a157c7ac88849, 0xb2c89b82f0fa3c15,
	0xaa1f028e82684ab1, 0xbca96148967f6735, 0xe5d3c82427a1b41c, 0x0ea4eeb1bca96135,
	0xe5d3c8d0d5eeebcf, 0x7c3b28409559c5d0, 0xfef392d342e4ecad, 0xcbcfdc8117a0cb5b,
	0xfa22f19cb927f67b, 0xe56d787a27be633d, 0x3c26dc818610eb67, 0x5079a428054a3a60,
	0xa74792b9e4348054, 0x9c4f74ab2e531cfc, 0x150c44bc6b29c7c9, 0xfc7dfc5efd897383,
	0xbb370cb9e434e49e, 0xb0f88e7a08b61d5f, 0x303f271295b9c55c, 0x7017c66cb17c136b,
	0xc75db93fcb6516bf, 0xa0f4e24ef43d56a4, 0xca2dfa64016f9fb9, 0x6efee9d2475e7707,
	0x3b64dc4f3ff46166, 0x504a5e3860bb2287, 0xf654b9d0dc08ef4f, 0x0e9f1a0e1c666e28,
	0x8e17812f86468b3f, 0xa47d8ff278aa2213, 0xe4b77f805a542e06, 0x1d4a04ab4f167369,
	0x32402ba6aa3e6854, 0x1be5e6cfcfb57598, 0x50e0eb8671603d0b, 0x2848c4146c8758b9,
	0x0b8f413346d0bbca, 0x7a77e53f191ba5ff, 0x4cb22c070a6d7530, 0x666ba8529cb66c9d,
	0x5ef264a66a157c7a, 0xc88849b2c89b82f0, 0xfa3c15aa1f028e82, 0x684ab1bca9614896,
	0x7f6735e5d3c82427, 0xa1b41c0ea4eeb1bc, 0xa96135e5d3c8d0d5, 0xeeebcf7c3b284095,
	0x59c5d0fef392d342, 0xe4ecadcbcfdc8117, 0xa0cb5bfa22f19cb9, 0x27f67be56d787a27,
	0xbe633d3c26dc8186, 0x10eb675079a42805, 0x4a3a60a74792b9e4, 0x3480549c4f74ab2e,
	0x531cfc150c44bc6b, 0x29c7c9fc7dfc5efd, 0x897383bb370cb9e4, 0x34e49eb0f88e7a08,
	0xb61d5f303f271295, 0xb9c55c7017c66cb1, 0x7c136bc75db93fcb, 0x6516bfa0f4e24ef4,
	0x3d56a4ca2dfa6401, 0x6f9fb96efee9d247, 0x5e77073b64dc4f3f, 0xf46166504a5e3860,
	0xbb2287f654b9d0dc, 0x08ef4f0e9f1a0e1c, 0x666e288e17812f86, 0x468b3fa47d8ff278,
	0xaa2213e4b77f805a, 0x542e061d4a04ab4f, 0x16736932402ba6aa, 0x3e68541be5e6cfcf,
	0xb5759850e0eb8671, 0x603d0b2848c4146c, 0x8758b90b8f413346, 0xd0bbca7a77e53f19,
	0x1ba5ff4cb22c070a, 0x6d7530666ba8529c, 0xb66c9d5ef264a66a, 0x157c7ac88849b2c8,
	0x9b82f0fa3c15aa1f, 0x028e82684ab1bca9, 0x6148967f6735e5d3, 0xc82427a1b41c0ea4,
	0xeeb1bca96135e5d3, 0xc8d0d5eeebcf7c3b, 0x28409559c5d0fef3, 0x92d342e4ecadcbcf,
	0xdc8117a0cb5bfa22, 0xf19cb927f67be56d, 0x787a27be633d3c26, 0xdc818610eb675079,
	0xa428054a3a60a747, 0x92b9e43480549c4f, 0x74ab2e531cfc150c, 0x44bc6b29c7c9fc7d,
	0xfc5efd897383bb37, 0x0cb9e434e49eb0f8, 0x8e7a08b61d5f303f, 0x271295b9c55c7017,
	0xc66cb17c136bc75d, 0xb93fcb6516bfa0f4, 0xe24ef43d56a4ca2d, 0xfa64016f9fb96efe,
	0xe9d2475e77073b64, 0xdc4f3ff46166504a, 0x5e3860bb2287f654, 0xb9d0dc08ef4f0e9f,
	0x1a0e1c666e288e17, 0x812f86468b3fa47d, 0x8ff278aa2213e4b7, 0x7f805a542e061d4a,
	0x04ab4f1673693240, 0x2ba6aa3e68541be5, 0xe6cfcfb5759850e0, 0xeb8671603d0b2848,
	0xc4146c8758b90b8f, 0x413346d0bbca7a77, 0xe53f191ba5ff4cb2, 0x2c070a6d7530666b,
	0xa8529cb66c9d5ef2, 0x64a66a157c7ac888, 0x49b2c89b82f0fa3c, 0x15aa1f028e82684a,
	0xb1bca96148967f67, 0x35e5d3c82427a1b4, 0x1c0ea4eeb1bca961, 0x35e5d3c8d0d5eeeb,
	0xcf7c3b28409559c5, 0xd0fef392d342e4ec, 0xadcbcfdc8117a0cb, 0x5bfa22f19cb927f6,
	0x7be56d787a27be63, 0x3d3c26dc818610eb, 0x675079a428054a3a, 0x60a74792b9e43480,
	0x549c4f74ab2e531c, 0xfc150c44bc6b29c7, 0xc9fc7dfc5efd8973, 0x83bb370cb9e434e4,
	0x9eb0f88e7a08b61d, 0x5f303f271295b9c5, 0x5c7017c66cb17c13, 0x6bc75db93fcb6516,
	0xbfa0f4e24ef43d56, 0xa4ca2dfa64016f9f, 0xb96efee9d2475e77, 0x073b64dc4f3ff461,
	0x66504a5e3860bb22, 0x87f654b9d0dc08ef, 0x4f0e9f1a0e1c666e, 0x288e17812f86468b,
	0x3fa47d8ff278aa22, 0x13e4b77f805a542e, 0x061d4a04ab4f1673, 0x6932402ba6aa3e68,
	0x541be5e6cfcfb575, 0x9850e0eb8671603d, 0x0b2848c4146c8758, 0xb90b8f413346d0bb,
	0xca7a77e53f191ba5, 0xff4cb22c070a6d75, 0x30666ba8529cb66c, 0x9d5ef264a66a157c,
	0x7ac88849b2c89b82, 0xf0fa3c15aa1f028e, 0x82684ab1bca96148, 0x967f6735e5d3c824,
	0x27a1b41c0ea4eeb1, 0xbca96135e5d3c8d0, 0xd5eeebcf7c3b2840, 0x9559c5d0fef392d3,
	0x42e4ecadcbcfdc81, 0x17a0cb5bfa22f19c, 0xb927f67be56d787a, 0x27be633d3c26dc81,
	0x8610eb675079a428, 0x054a3a60a74792b9, 0xe43480549c4f74ab, 0x2e531cfc150c44bc,
}

// Chunk represents a content-defined slice of data.
type Chunk struct {
	Offset   int64    `json:"offset"`
	Length   int      `json:"length"`
	Checksum [32]byte `json:"checksum"` // SHA-256
	Data     []byte   `json:"-"`
}

// Chunker splits an io.Reader into content-defined chunks using FastCDC.
type Chunker struct {
	r          io.Reader
	minSize    int
	avgSize    int
	maxSize    int
	normalSize int

	maskS uint64
	maskL uint64

	buf    []byte
	bufPos int
	bufLen int
	offset int64
	eof    bool
}

// NewChunker creates a new FastCDC chunker.
func NewChunker(r io.Reader, minSize, avgSize, maxSize int) *Chunker {
	if minSize <= 0 {
		minSize = DefaultMinSize
	}
	if avgSize <= 0 {
		avgSize = DefaultAvgSize
	}
	if maxSize <= 0 {
		maxSize = DefaultMaxSize
	}
	if minSize >= avgSize {
		minSize = avgSize / 2
	}
	if maxSize <= avgSize {
		maxSize = avgSize * 2
	}

	// Compute masks based on average size bits
	bits := 0
	for (1 << bits) < avgSize {
		bits++
	}
	maskS := (uint64(1) << (bits + 1)) - 1
	maskL := (uint64(1) << (bits - 1)) - 1
	normalSize := minSize + (avgSize-minSize)/2

	return &Chunker{
		r:          r,
		minSize:    minSize,
		avgSize:    avgSize,
		maxSize:    maxSize,
		normalSize: normalSize,
		maskS:      maskS,
		maskL:      maskL,
		buf:        make([]byte, maxSize*2),
	}
}

// Next returns the next content-defined chunk, or io.EOF when done.
func (c *Chunker) Next() (*Chunk, error) {
	for !c.eof && (c.bufLen-c.bufPos) < c.maxSize {
		if c.bufPos > 0 {
			copy(c.buf, c.buf[c.bufPos:c.bufLen])
			c.bufLen -= c.bufPos
			c.bufPos = 0
		}
		n, err := c.r.Read(c.buf[c.bufLen:])
		if n > 0 {
			c.bufLen += n
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				c.eof = true
			} else {
				return nil, err
			}
		}
	}

	available := c.bufLen - c.bufPos
	if available == 0 {
		return nil, io.EOF
	}

	if available <= c.minSize {
		data := make([]byte, available)
		copy(data, c.buf[c.bufPos:c.bufLen])
		chunk := &Chunk{
			Offset:   c.offset,
			Length:   available,
			Checksum: sha256.Sum256(data),
			Data:     data,
		}
		c.offset += int64(available)
		c.bufPos = c.bufLen
		return chunk, nil
	}

	chunkEnd := c.bufPos + c.minSize
	hardLimit := c.bufPos + c.maxSize
	if hardLimit > c.bufLen {
		hardLimit = c.bufLen
	}

	var fp uint64 = 0
	normalLimit := c.bufPos + c.normalSize
	if normalLimit > hardLimit {
		normalLimit = hardLimit
	}

	found := false

	// Phase 1: Small mask
	for ; chunkEnd < normalLimit; chunkEnd++ {
		fp = (fp << 1) + GearTable[c.buf[chunkEnd]]
		if (fp & c.maskS) == 0 {
			found = true
			chunkEnd++
			break
		}
	}

	// Phase 2: Large mask
	if !found {
		for ; chunkEnd < hardLimit; chunkEnd++ {
			fp = (fp << 1) + GearTable[c.buf[chunkEnd]]
			if (fp & c.maskL) == 0 {
				found = true
				chunkEnd++
				break
			}
		}
	}

	if !found {
		chunkEnd = hardLimit
	}

	length := chunkEnd - c.bufPos
	data := make([]byte, length)
	copy(data, c.buf[c.bufPos:chunkEnd])

	chunk := &Chunk{
		Offset:   c.offset,
		Length:   length,
		Checksum: sha256.Sum256(data),
		Data:     data,
	}

	c.offset += int64(length)
	c.bufPos = chunkEnd
	return chunk, nil
}

// ChunkLocation records where a chunk is located in an append-only packfile.
type ChunkLocation struct {
	PackfileID string `json:"packfile_id"`
	Offset     int64  `json:"offset"`
	Length     int    `json:"length"`
}

// ChunkIndex is a concurrency-safe in-memory CAS index to deduplicate uploads.
type ChunkIndex struct {
	mu     sync.RWMutex
	chunks map[[32]byte]ChunkLocation
}

func NewChunkIndex() *ChunkIndex {
	return &ChunkIndex{
		chunks: make(map[[32]byte]ChunkLocation),
	}
}

func (ci *ChunkIndex) Put(checksum [32]byte, loc ChunkLocation) {
	ci.mu.Lock()
	defer ci.mu.Unlock()
	ci.chunks[checksum] = loc
}

func (ci *ChunkIndex) Get(checksum [32]byte) (ChunkLocation, bool) {
	ci.mu.RLock()
	defer ci.mu.RUnlock()
	loc, ok := ci.chunks[checksum]
	return loc, ok
}

func (ci *ChunkIndex) Has(checksum [32]byte) bool {
	ci.mu.RLock()
	defer ci.mu.RUnlock()
	_, ok := ci.chunks[checksum]
	return ok
}

func (ci *ChunkIndex) Len() int {
	ci.mu.RLock()
	defer ci.mu.RUnlock()
	return len(ci.chunks)
}

// PackfileWriter writes chunks sequentially into an append-only packfile stream.
type PackfileWriter struct {
	w       io.Writer
	written int64
}

func NewPackfileWriter(w io.Writer) (*PackfileWriter, error) {
	n, err := w.Write([]byte(PackfileMagic))
	if err != nil {
		return nil, err
	}
	return &PackfileWriter{
		w:       w,
		written: int64(n),
	}, nil
}

// AppendChunk writes a chunk: [4 bytes length][32 bytes checksum][data]
func (pw *PackfileWriter) AppendChunk(chunk *Chunk) (int64, error) {
	chunkOffset := pw.written
	header := make([]byte, 4+32)
	binary.BigEndian.PutUint32(header[0:4], uint32(chunk.Length))
	copy(header[4:36], chunk.Checksum[:])

	if _, err := pw.w.Write(header); err != nil {
		return 0, fmt.Errorf("failed writing chunk header: %w", err)
	}
	if _, err := pw.w.Write(chunk.Data); err != nil {
		return 0, fmt.Errorf("failed writing chunk data: %w", err)
	}
	pw.written += int64(len(header) + chunk.Length)
	return chunkOffset, nil
}
