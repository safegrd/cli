package format

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// Node types in a tree.
const (
	NodeDir     = "dir"
	NodeFile    = "file"
	NodeSymlink = "symlink"
)

// Node is one entry of a directory. Name holds the raw bytes of the entry's
// name, which need not be UTF-8.
type Node struct {
	Name    string
	Type    string
	Mode    uint32
	UID     *uint32
	GID     *uint32
	ModTime time.Time

	// Files.
	Size    int64
	SHA256  string
	Content []ID

	// Directories.
	Subtree ID

	// Symlinks: the raw bytes of the link target.
	Target string

	// Inconsistent marks a file that kept changing while it was read.
	Inconsistent bool
}

// Tree is one directory: its entries, sorted by the raw bytes of their names.
type Tree struct {
	Entries []Node
}

// A tree blob's plaintext is JSON with keys in this order, each only where it
// applies, entries sorted by the raw bytes of the name:
//
//	name | name_b64, type, mode, uid, gid, mtime, size, sha256, content,
//	subtree, target, inconsistent
//
// A name that is not valid UTF-8 is written as name_b64, standard base64 of
// its bytes. A symlink target is written the same way, as target or
// target_b64.
type wireNode struct {
	Name         string    `json:"name,omitempty"`
	NameB64      string    `json:"name_b64,omitempty"`
	Type         string    `json:"type"`
	Mode         uint32    `json:"mode"`
	UID          *uint32   `json:"uid,omitempty"`
	GID          *uint32   `json:"gid,omitempty"`
	MTime        string    `json:"mtime"`
	Size         *int64    `json:"size,omitempty"`
	SHA256       string    `json:"sha256,omitempty"`
	Content      *[]string `json:"content,omitempty"`
	Subtree      string    `json:"subtree,omitempty"`
	Target       string    `json:"target,omitempty"`
	TargetB64    string    `json:"target_b64,omitempty"`
	Inconsistent bool      `json:"inconsistent,omitempty"`
}

type wireTree struct {
	Entries []wireNode `json:"entries"`
}

// TimeString formats t as RFC 3339 with nanoseconds, in UTC.
func TimeString(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// EncodeTree returns a tree blob's plaintext. It refuses a tree that is not
// sorted, names an entry twice, or is otherwise one a reader would refuse,
// so the writer cannot store what it could not read back.
func EncodeTree(t Tree) ([]byte, error) {
	if err := t.validate(); err != nil {
		return nil, err
	}
	w := wireTree{Entries: make([]wireNode, 0, len(t.Entries))}
	for _, n := range t.Entries {
		wn := wireNode{Type: n.Type, Mode: n.Mode, UID: n.UID, GID: n.GID, MTime: TimeString(n.ModTime)}
		if utf8.ValidString(n.Name) {
			wn.Name = n.Name
		} else {
			wn.NameB64 = base64.StdEncoding.EncodeToString([]byte(n.Name))
		}
		switch n.Type {
		case NodeFile:
			size := n.Size
			wn.Size = &size
			wn.SHA256 = n.SHA256
			content := make([]string, len(n.Content))
			for i, id := range n.Content {
				content[i] = id.String()
			}
			wn.Content = &content
			wn.Inconsistent = n.Inconsistent
		case NodeDir:
			wn.Subtree = n.Subtree.String()
		case NodeSymlink:
			if utf8.ValidString(n.Target) {
				wn.Target = n.Target
			} else {
				wn.TargetB64 = base64.StdEncoding.EncodeToString([]byte(n.Target))
			}
		}
		w.Entries = append(w.Entries, wn)
	}
	return Marshal(w)
}

// DecodeTree parses and validates a tree blob's plaintext.
func DecodeTree(b []byte) (Tree, error) {
	var w wireTree
	if err := Unmarshal(b, &w); err != nil {
		return Tree{}, fmt.Errorf("tree: %w", err)
	}
	if w.Entries == nil {
		return Tree{}, fmt.Errorf("tree: no entries list")
	}
	t := Tree{Entries: make([]Node, 0, len(w.Entries))}
	for i, wn := range w.Entries {
		n := Node{Type: wn.Type, Mode: wn.Mode, UID: wn.UID, GID: wn.GID}
		switch {
		case wn.Name != "" && wn.NameB64 != "":
			return Tree{}, fmt.Errorf("tree: entry %d has both name and name_b64", i)
		case wn.NameB64 != "":
			raw, err := base64.StdEncoding.DecodeString(wn.NameB64)
			if err != nil {
				return Tree{}, fmt.Errorf("tree: entry %d: name_b64: %w", i, err)
			}
			if utf8.Valid(raw) {
				return Tree{}, fmt.Errorf("tree: entry %d: name_b64 holds valid UTF-8, which is written as name", i)
			}
			n.Name = string(raw)
		default:
			n.Name = wn.Name
		}
		mt, err := time.Parse(time.RFC3339Nano, wn.MTime)
		if err != nil {
			return Tree{}, fmt.Errorf("tree: entry %d: mtime: %w", i, err)
		}
		n.ModTime = mt.UTC()
		switch wn.Type {
		case NodeFile:
			if wn.Size == nil || wn.Content == nil {
				return Tree{}, fmt.Errorf("tree: file entry %d has no size or content", i)
			}
			if wn.Subtree != "" || wn.Target != "" || wn.TargetB64 != "" {
				return Tree{}, fmt.Errorf("tree: file entry %d carries a directory's or a link's field", i)
			}
			n.Size = *wn.Size
			n.SHA256 = wn.SHA256
			n.Inconsistent = wn.Inconsistent
			n.Content = make([]ID, len(*wn.Content))
			for j, s := range *wn.Content {
				id, err := ParseID(s)
				if err != nil {
					return Tree{}, fmt.Errorf("tree: entry %d content %d: %w", i, j, err)
				}
				n.Content[j] = id
			}
		case NodeDir:
			if wn.Size != nil || wn.Content != nil || wn.SHA256 != "" || wn.Target != "" || wn.TargetB64 != "" || wn.Inconsistent {
				return Tree{}, fmt.Errorf("tree: directory entry %d carries a file's or a link's field", i)
			}
			id, err := ParseID(wn.Subtree)
			if err != nil {
				return Tree{}, fmt.Errorf("tree: entry %d subtree: %w", i, err)
			}
			n.Subtree = id
		case NodeSymlink:
			if wn.Size != nil || wn.Content != nil || wn.SHA256 != "" || wn.Subtree != "" || wn.Inconsistent {
				return Tree{}, fmt.Errorf("tree: symlink entry %d carries a file's or a directory's field", i)
			}
			switch {
			case wn.Target != "" && wn.TargetB64 != "":
				return Tree{}, fmt.Errorf("tree: entry %d has both target and target_b64", i)
			case wn.TargetB64 != "":
				raw, err := base64.StdEncoding.DecodeString(wn.TargetB64)
				if err != nil {
					return Tree{}, fmt.Errorf("tree: entry %d: target_b64: %w", i, err)
				}
				if utf8.Valid(raw) {
					return Tree{}, fmt.Errorf("tree: entry %d: target_b64 holds valid UTF-8, which is written as target", i)
				}
				n.Target = string(raw)
			default:
				n.Target = wn.Target
			}
		default:
			return Tree{}, fmt.Errorf("tree: entry %d has type %q, not dir, file or symlink", i, wn.Type)
		}
		t.Entries = append(t.Entries, n)
	}
	if err := t.validate(); err != nil {
		return Tree{}, err
	}
	return t, nil
}

// ValidName reports why name cannot be a tree entry's name, or nil.
func ValidName(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("an empty name")
	case name == "." || name == "..":
		return fmt.Errorf("the name %q", name)
	case strings.ContainsAny(name, "/\x00"):
		return fmt.Errorf("the name %q holds a slash or NUL", name)
	}
	return nil
}

func (t Tree) validate() error {
	for i, n := range t.Entries {
		if err := ValidName(n.Name); err != nil {
			return fmt.Errorf("tree: entry %d: %w", i, err)
		}
		if i > 0 && bytes.Compare([]byte(t.Entries[i-1].Name), []byte(n.Name)) >= 0 {
			return fmt.Errorf("tree: entry %q is out of order or repeated", n.Name)
		}
		if n.Mode > 0o7777 {
			return fmt.Errorf("tree: entry %q has mode %o beyond the permission bits", n.Name, n.Mode)
		}
		switch n.Type {
		case NodeFile:
			if n.Size < 0 {
				return fmt.Errorf("tree: file %q has a negative size", n.Name)
			}
			if len(n.SHA256) != 64 || !lowerHex.MatchString(n.SHA256) {
				return fmt.Errorf("tree: file %q has no SHA-256", n.Name)
			}
			if n.Size > 0 && len(n.Content) == 0 {
				return fmt.Errorf("tree: file %q has %d bytes and no content", n.Name, n.Size)
			}
		case NodeDir:
			if n.Subtree.IsZero() {
				return fmt.Errorf("tree: directory %q has no subtree", n.Name)
			}
		case NodeSymlink:
			if n.Target == "" {
				return fmt.Errorf("tree: symlink %q has no target", n.Name)
			}
		default:
			return fmt.Errorf("tree: entry %q has type %q", n.Name, n.Type)
		}
	}
	return nil
}
