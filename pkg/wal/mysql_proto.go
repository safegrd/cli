package wal

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // mysql_native_password is defined over SHA-1
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/dump"
)

// A binary log reader speaks enough of the MySQL protocol to log in and ask
// for the binary log: the handshake, mysql_native_password and
// caching_sha2_password (over TLS, or with the server's RSA key), simple
// statements, and COM_BINLOG_DUMP. It never decodes a row.

const (
	capLongPassword   = 0x00000001
	capLongFlag       = 0x00000004
	capConnectWithDB  = 0x00000008
	capProtocol41     = 0x00000200
	capSSL            = 0x00000800
	capTransactions   = 0x00002000
	capSecureConn     = 0x00008000
	capMultiResults   = 0x00020000
	capPluginAuth     = 0x00080000
	capPluginAuthLenc = 0x00200000

	comQuery      = 0x03
	comBinlogDump = 0x12

	maxPacket = 1<<24 - 1
)

// mysqlConn is one connection in the MySQL protocol.
type mysqlConn struct {
	nc      net.Conn
	r       *bufio.Reader
	seq     byte
	Version string
	MariaDB bool
}

// MySQLError is an error packet from the server.
type MySQLError struct {
	Code    uint16
	State   string
	Message string
}

func (e *MySQLError) Error() string {
	if e.State != "" {
		return fmt.Sprintf("Error %d (%s): %s", e.Code, e.State, e.Message)
	}
	return fmt.Sprintf("Error %d: %s", e.Code, e.Message)
}

func parseErrPacket(p []byte) error {
	e := &MySQLError{}
	if len(p) >= 3 {
		e.Code = binary.LittleEndian.Uint16(p[1:3])
		rest := p[3:]
		if len(rest) >= 6 && rest[0] == '#' {
			e.State, rest = string(rest[1:6]), rest[6:]
		}
		e.Message = string(rest)
	}
	return e
}

func (c *mysqlConn) readPacket() ([]byte, error) {
	var out []byte
	for {
		var h [4]byte
		if _, err := io.ReadFull(c.r, h[:]); err != nil {
			return nil, err
		}
		n := int(h[0]) | int(h[1])<<8 | int(h[2])<<16
		c.seq = h[3] + 1
		buf := make([]byte, n)
		if _, err := io.ReadFull(c.r, buf); err != nil {
			return nil, err
		}
		if out == nil {
			out = buf
		} else {
			out = append(out, buf...)
		}
		if n < maxPacket {
			return out, nil
		}
	}
}

func (c *mysqlConn) writePacket(p []byte) error {
	for {
		n := min(len(p), maxPacket)
		h := []byte{byte(n), byte(n >> 8), byte(n >> 16), c.seq}
		c.seq++
		if _, err := c.nc.Write(append(h, p[:n]...)); err != nil {
			return err
		}
		p = p[n:]
		if n < maxPacket {
			return nil
		}
	}
}

// dialMySQL connects and logs in.
func dialMySQL(ctx context.Context, ci dump.MySQLConnInfo) (*mysqlConn, error) {
	d := net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	nc, err := d.DialContext(ctx, "tcp", ci.Addr)
	if err != nil {
		return nil, err
	}
	c := &mysqlConn{nc: nc, r: bufio.NewReaderSize(nc, 64<<10)}
	_ = nc.SetDeadline(time.Now().Add(30 * time.Second))
	if err := c.handshake(ci); err != nil {
		nc.Close()
		return nil, err
	}
	_ = nc.SetDeadline(time.Time{})
	return c, nil
}

func (c *mysqlConn) handshake(ci dump.MySQLConnInfo) error {
	p, err := c.readPacket()
	if err != nil {
		return fmt.Errorf("reading the server's greeting: %w", err)
	}
	if len(p) > 0 && p[0] == 0xff {
		return parseErrPacket(p)
	}
	if len(p) < 1 || p[0] != 10 {
		return errors.New("the server does not speak protocol version 10")
	}
	i := 1
	end := strings.IndexByte(string(p[i:]), 0)
	if end < 0 {
		return errors.New("the server's greeting is malformed")
	}
	c.Version = string(p[i : i+end])
	c.MariaDB = strings.Contains(strings.ToLower(c.Version), "mariadb")
	i += end + 1 + 4
	if len(p) < i+8+1+2 {
		return errors.New("the server's greeting is short")
	}
	scramble := append([]byte{}, p[i:i+8]...)
	i += 9
	caps := uint32(binary.LittleEndian.Uint16(p[i:]))
	i += 2
	authLen := 0
	plugin := "mysql_native_password"
	if len(p) >= i+1+2+2+1+10 {
		i += 1 + 2
		caps |= uint32(binary.LittleEndian.Uint16(p[i:])) << 16
		i += 2
		authLen = int(p[i])
		i += 1 + 10
		if caps&capSecureConn != 0 {
			n := max(13, authLen-8)
			if len(p) >= i+n {
				part := p[i : i+n]
				if k := strings.IndexByte(string(part), 0); k >= 0 {
					part = part[:k]
				}
				scramble = append(scramble, part...)
				i += n
			}
		}
		if caps&capPluginAuth != 0 && i < len(p) {
			name := p[i:]
			if k := strings.IndexByte(string(name), 0); k >= 0 {
				name = name[:k]
			}
			plugin = string(name)
		}
	}

	ours := uint32(capLongPassword | capLongFlag | capProtocol41 | capTransactions | capSecureConn | capMultiResults | capPluginAuth | capPluginAuthLenc)
	tlsOn := false
	if ci.TLS != nil {
		if caps&capSSL == 0 {
			if !ci.Preferred {
				return errors.New("the server does not offer TLS, and the URL asks for it")
			}
		} else {
			ours |= capSSL
			req := make([]byte, 32)
			binary.LittleEndian.PutUint32(req, ours)
			binary.LittleEndian.PutUint32(req[4:], maxPacket)
			req[8] = 45 // utf8mb4_general_ci
			if err := c.writePacket(req); err != nil {
				return err
			}
			tc := tls.Client(c.nc, ci.TLS)
			if err := tc.Handshake(); err != nil {
				return fmt.Errorf("TLS handshake: %w", err)
			}
			c.nc, c.r = tc, bufio.NewReaderSize(tc, 64<<10)
			tlsOn = true
		}
	}
	if ci.Database != "" {
		ours |= capConnectWithDB
	}
	auth, err := mysqlScramble(plugin, ci.Password, scramble)
	if err != nil {
		return err
	}
	resp := make([]byte, 32, 128)
	binary.LittleEndian.PutUint32(resp, ours)
	binary.LittleEndian.PutUint32(resp[4:], maxPacket)
	resp[8] = 45
	resp = append(resp, ci.User...)
	resp = append(resp, 0, byte(len(auth)))
	resp = append(resp, auth...)
	if ci.Database != "" {
		resp = append(resp, ci.Database...)
		resp = append(resp, 0)
	}
	resp = append(resp, plugin...)
	resp = append(resp, 0)
	if err := c.writePacket(resp); err != nil {
		return err
	}
	return c.authResult(ci, plugin, scramble, tlsOn)
}

// mysqlScramble is the first answer to the server's challenge.
func mysqlScramble(plugin, password string, scramble []byte) ([]byte, error) {
	if password == "" {
		return nil, nil
	}
	if len(scramble) > 20 {
		scramble = scramble[:20]
	}
	switch plugin {
	case "mysql_native_password":
		h1 := sha1.Sum([]byte(password)) //nolint:gosec
		h2 := sha1.Sum(h1[:])            //nolint:gosec
		h := sha1.New()                  //nolint:gosec
		h.Write(scramble)
		h.Write(h2[:])
		h3 := h.Sum(nil)
		for i := range h3 {
			h3[i] ^= h1[i]
		}
		return h3, nil
	case "caching_sha2_password":
		m1 := sha256.Sum256([]byte(password))
		m2 := sha256.Sum256(m1[:])
		h := sha256.New()
		h.Write(m2[:])
		h.Write(scramble)
		m3 := h.Sum(nil)
		for i := range m3 {
			m3[i] ^= m1[i]
		}
		return m3, nil
	}
	return nil, fmt.Errorf("the server asks for the %s authentication plugin; give this account mysql_native_password or caching_sha2_password", plugin)
}

func (c *mysqlConn) authResult(ci dump.MySQLConnInfo, plugin string, scramble []byte, tlsOn bool) error {
	for range 8 {
		p, err := c.readPacket()
		if err != nil {
			return fmt.Errorf("logging in: %w", err)
		}
		if len(p) == 0 {
			return errors.New("logging in: an empty packet")
		}
		switch p[0] {
		case 0x00:
			return nil
		case 0xff:
			return parseErrPacket(p)
		case 0xfe: // switch to another plugin
			if len(p) == 1 {
				return errors.New("the server asks for the old pre-4.1 password scheme")
			}
			rest := p[1:]
			k := strings.IndexByte(string(rest), 0)
			if k < 0 {
				return errors.New("a malformed authentication switch")
			}
			plugin = string(rest[:k])
			scramble = rest[k+1:]
			if n := len(scramble); n > 0 && scramble[n-1] == 0 {
				scramble = scramble[:n-1]
			}
			auth, err := mysqlScramble(plugin, ci.Password, scramble)
			if err != nil {
				return err
			}
			if err := c.writePacket(auth); err != nil {
				return err
			}
		case 0x01: // more data
			if plugin != "caching_sha2_password" || len(p) < 2 {
				return fmt.Errorf("unexpected authentication data for %s", plugin)
			}
			switch p[1] {
			case 3: // fast authentication worked; OK follows
			case 4: // full authentication
				pw := append([]byte(ci.Password), 0)
				if tlsOn {
					if err := c.writePacket(pw); err != nil {
						return err
					}
					continue
				}
				if err := c.writePacket([]byte{2}); err != nil { // ask for the public key
					return err
				}
				kp, err := c.readPacket()
				if err != nil {
					return err
				}
				if len(kp) < 2 || kp[0] != 0x01 {
					return errors.New("the server sent no public key for caching_sha2_password")
				}
				block, _ := pem.Decode(kp[1:])
				if block == nil {
					return errors.New("the server's public key does not parse")
				}
				pub, err := x509.ParsePKIXPublicKey(block.Bytes)
				if err != nil {
					return fmt.Errorf("the server's public key: %w", err)
				}
				rk, ok := pub.(*rsa.PublicKey)
				if !ok {
					return errors.New("the server's public key is not RSA")
				}
				sc := scramble
				if len(sc) > 20 {
					sc = sc[:20]
				}
				for i := range pw {
					pw[i] ^= sc[i%len(sc)]
				}
				enc, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, rk, pw, nil) //nolint:gosec
				if err != nil {
					return err
				}
				if err := c.writePacket(enc); err != nil {
					return err
				}
			default:
				return fmt.Errorf("unexpected caching_sha2_password state %d", p[1])
			}
		default:
			return fmt.Errorf("unexpected packet 0x%02x while logging in", p[0])
		}
	}
	return errors.New("logging in took too many rounds")
}

// exec runs a statement and discards any rows it returns.
func (c *mysqlConn) exec(sql string) error {
	c.seq = 0
	if err := c.writePacket(append([]byte{comQuery}, sql...)); err != nil {
		return err
	}
	p, err := c.readPacket()
	if err != nil {
		return err
	}
	switch {
	case len(p) == 0:
		return errors.New("an empty answer")
	case p[0] == 0x00:
		return nil
	case p[0] == 0xff:
		return parseErrPacket(p)
	}
	// A result set: column definitions to an EOF, rows to an EOF.
	eofs := 0
	for eofs < 2 {
		p, err := c.readPacket()
		if err != nil {
			return err
		}
		if len(p) > 0 && p[0] == 0xff {
			return parseErrPacket(p)
		}
		if len(p) > 0 && p[0] == 0xfe && len(p) < 9 {
			eofs++
		}
	}
	return nil
}

// dumpBinlog asks for the binary log from file at pos, following it as it
// grows.
func (c *mysqlConn) dumpBinlog(file string, pos uint32, serverID uint32, flags uint16) error {
	c.seq = 0
	b := make([]byte, 11, 11+len(file))
	b[0] = comBinlogDump
	binary.LittleEndian.PutUint32(b[1:], pos)
	binary.LittleEndian.PutUint16(b[5:], flags)
	binary.LittleEndian.PutUint32(b[7:], serverID)
	b = append(b, file...)
	return c.writePacket(b)
}

// readEvent returns the next binary log event, or io.EOF when the server
// ends the stream.
func (c *mysqlConn) readEvent() ([]byte, error) {
	p, err := c.readPacket()
	if err != nil {
		return nil, err
	}
	switch {
	case len(p) == 0:
		return nil, errors.New("an empty packet in the binary log stream")
	case p[0] == 0xff:
		return nil, parseErrPacket(p)
	case p[0] == 0xfe && len(p) < 9:
		return nil, io.EOF
	case p[0] != 0x00:
		return nil, fmt.Errorf("unexpected packet 0x%02x in the binary log stream", p[0])
	}
	return p[1:], nil
}

func (c *mysqlConn) Close() error { return c.nc.Close() }
