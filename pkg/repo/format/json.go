package format

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// Marshal encodes v with its keys in struct order, no insignificant
// whitespace, no trailing newline and no HTML escaping. A tree's id is the
// hash of these bytes, so the same directory must encode the same way.
func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// Unmarshal decodes exactly one JSON value into v and refuses keys v does not
// name and anything after the value.
func Unmarshal(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("unexpected data after the JSON value")
	}
	return nil
}
