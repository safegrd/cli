package write

import (
	"crypto/md5"
	"fmt"

	"filippo.io/age"
	"github.com/safegrd/cli/pkg/repo/format"
	"github.com/safegrd/cli/pkg/repo/seal"
)

// packer gathers sealed blobs of one type into a pack. Each pack has its own
// random key, wrapped to the recipient in the header and forgotten once the
// pack is closed.
type packer struct {
	kind    byte
	target  int
	rec     age.Recipient
	id      string
	buf     []byte
	entries []format.BlobEntry
	sealer  *seal.Sealer
}

// sealedPack is a closed pack, ready to upload.
type sealedPack struct {
	id      string
	body    []byte
	md5     [16]byte
	entries []format.BlobEntry
}

func newPacker(kind byte, target int, rec age.Recipient) *packer {
	return &packer{kind: kind, target: target, rec: rec}
}

func (p *packer) start() error {
	key, err := seal.NewKey()
	if err != nil {
		return err
	}
	wrapped, err := seal.WrapKey(key, p.rec)
	if err != nil {
		return fmt.Errorf("wrapping a pack key: %w", err)
	}
	header, err := format.EncodePackHeader(wrapped)
	if err != nil {
		return err
	}
	s, err := seal.NewSealer(key)
	if err != nil {
		return err
	}
	p.id, p.sealer, p.entries = format.NewRandomID(), s, nil
	p.buf = make([]byte, 0, p.target+p.target/4)
	p.buf = append(p.buf, header...)
	return nil
}

// add seals one blob into the open pack, opening one if needed.
func (p *packer) add(id format.ID, plain []byte) error {
	if p.sealer == nil {
		if err := p.start(); err != nil {
			return err
		}
	}
	payload, tb := seal.Payload(p.kind, plain)
	rec, err := p.sealer.Record(id, tb, payload)
	if err != nil {
		return err
	}
	p.entries = append(p.entries, format.BlobEntry{
		ID: id.String(), Type: tb, Offset: int64(len(p.buf)), Length: int64(len(rec)), RawLength: int64(len(plain)),
	})
	p.buf = append(p.buf, rec...)
	return nil
}

func (p *packer) full() bool  { return p.sealer != nil && len(p.buf) >= p.target }
func (p *packer) empty() bool { return p.sealer == nil || len(p.entries) == 0 }

// finish writes the trailer and footer and returns the closed pack. The key
// goes out of scope with the sealer.
func (p *packer) finish() (*sealedPack, error) {
	if p.empty() {
		p.sealer = nil
		return nil, nil
	}
	plain, err := format.EncodeTrailer(format.Trailer{Blobs: p.entries})
	if err != nil {
		return nil, err
	}
	trailer, err := p.sealer.Trailer(p.id, plain)
	if err != nil {
		return nil, err
	}
	body := append(p.buf, trailer...)
	body = append(body, format.EncodePackFooter(len(trailer))...)
	sp := &sealedPack{id: p.id, body: body, md5: md5.Sum(body), entries: p.entries}
	p.buf, p.entries, p.sealer, p.id = nil, nil, nil, ""
	return sp, nil
}
