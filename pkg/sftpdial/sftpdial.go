// Package sftpdial opens an SFTP session to the server a type: sftp storage
// names, after checking the server's host key, and shares it between the
// archive provider and the repository store.
//
// The session is opened on first use and closed once nothing has used it
// for a while, so a long-running daemon that opens storage for every run
// does not keep one SSH connection per run.
package sftpdial

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"github.com/safegrd/cli/pkg/config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// idleClose is how long an unused session stays open.
const idleClose = 30 * time.Second

// dialTimeout bounds the TCP connect and the SSH handshake, so a server
// that does not answer fails the run instead of stalling it.
const dialTimeout = 30 * time.Second

// Conn is one server, dialled on demand.
type Conn struct {
	cfg  config.SFTPConfig
	addr string
	auth []ssh.AuthMethod

	mu     sync.Mutex
	client *sftp.Client
	sshc   *ssh.Client
	users  int
	timer  *time.Timer
}

// New checks cfg and prepares to dial it. Password and PrivateKey are the
// secrets themselves: a value still reading env: or file: was not resolved
// by the caller and is refused rather than sent as a password.
func New(cfg config.SFTPConfig) (*Conn, error) {
	if cfg.Host == "" || cfg.User == "" || cfg.Path == "" {
		return nil, errors.New("sftp storage needs host, user and path")
	}
	if cfg.KnownHosts == "" && cfg.HostKey == "" {
		return nil, errors.New("sftp storage needs known_hosts or host_key, so the server's key is checked")
	}
	for name, v := range map[string]string{"password": cfg.Password, "private_key": cfg.PrivateKey} {
		if strings.HasPrefix(v, "env:") || strings.HasPrefix(v, "file:") {
			return nil, fmt.Errorf("storage.sftp.%s was not resolved from %s", name, strings.SplitN(v, ":", 2)[0]+":")
		}
	}
	c := &Conn{cfg: cfg}
	port := cfg.Port
	if port == 0 {
		port = 22
	}
	c.addr = net.JoinHostPort(cfg.Host, strconv.Itoa(port))
	if cfg.PrivateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(cfg.PrivateKey))
		if err != nil {
			var pp *ssh.PassphraseMissingError
			if errors.As(err, &pp) {
				return nil, errors.New("storage.sftp.private_key is protected by a passphrase, which safegrd does not read: use a key without one, kept readable only by this host's backup user")
			}
			return nil, fmt.Errorf("storage.sftp.private_key: %w", err)
		}
		c.auth = append(c.auth, ssh.PublicKeys(signer))
	}
	if cfg.Password != "" {
		pw := cfg.Password
		c.auth = append(c.auth, ssh.Password(pw), ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
			out := make([]string, len(qs))
			for i := range qs {
				out[i] = pw
			}
			return out, nil
		}))
	}
	return c, nil
}

// Path is the directory on the server, as configured.
func (c *Conn) Path() string { return c.cfg.Path }

// Describe names the server and directory, with no secret.
func (c *Conn) Describe() string { return c.cfg.URL() }

// URI is Describe with a path below the directory joined on, for a
// snapshot's storage URI.
func (c *Conn) URI(rel string) string {
	rel = strings.Trim(rel, "/")
	if rel == "" {
		return c.Describe()
	}
	return c.Describe() + "/" + rel
}

// Use returns the session, dialling it if needed, and the function that
// hands it back. Every Use is followed by its release.
func (c *Conn) Use(ctx context.Context) (*sftp.Client, func(), error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	if c.client == nil {
		cl, sc, err := c.dial(ctx)
		if err != nil {
			return nil, nil, err
		}
		c.client, c.sshc = cl, sc
		go func(cl *sftp.Client) {
			// A dropped connection is dialled again on the next use.
			_ = cl.Wait()
			c.mu.Lock()
			if c.client == cl {
				c.client, c.sshc = nil, nil
			}
			c.mu.Unlock()
		}(cl)
	}
	c.users++
	cl := c.client
	var once sync.Once
	return cl, func() { once.Do(c.release) }, nil
}

func (c *Conn) release() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.users--
	if c.users > 0 || c.client == nil {
		return
	}
	c.timer = time.AfterFunc(idleClose, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.users == 0 {
			c.closeLocked()
		}
	})
}

// Close closes the session now.
func (c *Conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeLocked()
}

func (c *Conn) closeLocked() error {
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	if c.client == nil {
		return nil
	}
	err := c.client.Close()
	if c.sshc != nil {
		_ = c.sshc.Close() // the sftp client's close already ended the session
	}
	c.client, c.sshc = nil, nil
	return err
}

func (c *Conn) dial(ctx context.Context) (*sftp.Client, *ssh.Client, error) {
	check, algos, err := c.hostKeyCheck()
	if err != nil {
		return nil, nil, err
	}
	var refused error
	cfg := &ssh.ClientConfig{
		User: c.cfg.User,
		Auth: c.auth,
		HostKeyCallback: func(host string, remote net.Addr, key ssh.PublicKey) error {
			if err := check(host, remote, key); err != nil {
				refused = err
				return err
			}
			return nil
		},
		HostKeyAlgorithms: algos,
		Timeout:           dialTimeout,
	}
	d := net.Dialer{Timeout: dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return nil, nil, fmt.Errorf("connecting to the SFTP server %s: %w", c.addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(dialTimeout))
	sc, chans, reqs, err := ssh.NewClientConn(conn, c.addr, cfg)
	if err != nil {
		conn.Close()
		if refused != nil {
			return nil, nil, refused
		}
		return nil, nil, fmt.Errorf("signing in to the SFTP server %s as %s: %w", c.addr, c.cfg.User, err)
	}
	_ = conn.SetDeadline(time.Time{})
	client := ssh.NewClient(sc, chans, reqs)
	sf, err := sftp.NewClient(client, sftp.UseConcurrentWrites(true))
	if err != nil {
		client.Close()
		return nil, nil, fmt.Errorf("starting SFTP on %s (the account may allow a shell but not the sftp subsystem): %w", c.addr, err)
	}
	return sf, client, nil
}

// preferredHostKeys asks a server for its ed25519 key first. A server has
// one key of each type and presents one, by the order the client asks in;
// the fingerprint an administrator reads out is usually the ed25519 key's
// (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`), so that is the one
// asked for when the client has nothing else to go by.
var preferredHostKeys = []string{
	ssh.KeyAlgoED25519,
	ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256,
}

// hostKeyCheck is the check of the server's key: the pinned fingerprint, or
// the known_hosts file. With known_hosts it also returns the key types the
// file holds for this server, so the server is asked for one of those and
// not refused for offering another kind of key it also has.
func (c *Conn) hostKeyCheck() (ssh.HostKeyCallback, []string, error) {
	if c.cfg.HostKey != "" {
		want := strings.TrimSpace(c.cfg.HostKey)
		return func(_ string, _ net.Addr, key ssh.PublicKey) error {
			got := ssh.FingerprintSHA256(key)
			if got != want {
				return fmt.Errorf("the SFTP server %s presented host key %s (%s), not %s, the one storage.sftp.host_key pins. "+
					"Nothing was sent. If the server's key was changed on purpose, check the new fingerprint with its administrator and pin that",
					c.addr, got, key.Type(), want)
			}
			return nil
		}, preferredHostKeys, nil
	}
	file := expandHome(c.cfg.KnownHosts)
	cb, err := knownhosts.New(file)
	if err != nil {
		return nil, nil, fmt.Errorf("storage.sftp.known_hosts: %w", err)
	}
	check := func(host string, remote net.Addr, key ssh.PublicKey) error {
		err := cb(host, remote, key)
		var ke *knownhosts.KeyError
		switch {
		case err == nil:
			return nil
		case errors.As(err, &ke) && len(ke.Want) == 0:
			return fmt.Errorf("the SFTP server %s is not in %s, so its host key %s cannot be checked. Nothing was sent. "+
				"Check that fingerprint with the server's administrator, then add the server with `ssh-keyscan -p %d %s >> %s`, "+
				"or set storage.sftp.host_key: %s",
				c.addr, file, ssh.FingerprintSHA256(key), c.port(), c.cfg.Host, file, ssh.FingerprintSHA256(key))
		case errors.As(err, &ke):
			return fmt.Errorf("the SFTP server %s presented host key %s (%s), which does not match the one %s lists for it. "+
				"Nothing was sent. If the server's key was changed on purpose, check the new fingerprint with its administrator and update %s",
				c.addr, ssh.FingerprintSHA256(key), key.Type(), file, file)
		}
		return fmt.Errorf("checking the SFTP server's host key against %s: %w", file, err)
	}
	return check, c.knownAlgorithms(cb), nil
}

// knownAlgorithms asks the known_hosts callback which keys it holds for the
// server, by offering it one it cannot hold.
func (c *Conn) knownAlgorithms(cb ssh.HostKeyCallback) []string {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil
	}
	probe, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil
	}
	var ke *knownhosts.KeyError
	if err := cb(c.addr, &net.TCPAddr{IP: net.IPv4zero, Port: c.port()}, probe); !errors.As(err, &ke) || len(ke.Want) == 0 {
		// Not listed: the refusal names the key the server presents, so
		// ask for the one an administrator is likely to read out.
		return preferredHostKeys
	}
	var algos []string
	seen := map[string]bool{}
	add := func(a string) {
		if !seen[a] {
			seen[a] = true
			algos = append(algos, a)
		}
	}
	for _, k := range ke.Want {
		switch t := k.Key.Type(); t {
		case ssh.KeyAlgoRSA:
			add(ssh.KeyAlgoRSASHA512)
			add(ssh.KeyAlgoRSASHA256)
			add(ssh.KeyAlgoRSA)
		default:
			add(t)
		}
	}
	return algos
}

func (c *Conn) port() int {
	if c.cfg.Port == 0 {
		return 22
	}
	return c.cfg.Port
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}
