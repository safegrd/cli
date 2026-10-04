package cli

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
)

// databaseTLSWarning says when a database URL would carry its password to a
// host on the network without verifying who it talks to. It returns "" for a
// loopback or socket host, for a verified mode, and for a URL it cannot read.
//
// PostgreSQL: libpq's default sslmode is prefer, which negotiates TLS but
// checks no certificate, and disable sends the password in the clear on every
// backup. MySQL: the driver takes tls=skip-verify without a word. IMAP already
// refuses to offer a skip-verify option, so this makes the three one rule.
// The URL itself is never part of the message.
func databaseTLSWarning(raw string) string {
	lower := strings.ToLower(raw)
	switch {
	case strings.HasPrefix(lower, "postgres://"), strings.HasPrefix(lower, "postgresql://"):
		return postgresTLSWarning(raw)
	case strings.HasPrefix(lower, "mysql://"), strings.HasPrefix(lower, "mariadb://"):
		return mysqlTLSWarning(raw)
	}
	return ""
}

func postgresTLSWarning(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	q := u.Query()
	hosts := strings.Split(u.Host, ",")
	if h := q.Get("host"); h != "" {
		hosts = append(hosts, strings.Split(h, ",")...)
	}
	if h := q.Get("hostaddr"); h != "" {
		hosts = append(hosts, strings.Split(h, ",")...)
	}
	if allLoopback(hosts) {
		return ""
	}
	mode := strings.ToLower(q.Get("sslmode"))
	switch mode {
	case "":
		return "its connection URL sets no sslmode, so libpq uses prefer, which encrypts without checking the server's certificate; set sslmode=verify-full"
	case "disable":
		return "its connection URL sets sslmode=disable, which sends the password in the clear on every backup; set sslmode=verify-full"
	case "allow", "prefer":
		return "its connection URL sets sslmode=" + mode + ", which may send the password in the clear and checks no certificate; set sslmode=verify-full"
	}
	return ""
}

func mysqlTLSWarning(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || allLoopback([]string{u.Host}) {
		return ""
	}
	q := u.Query()
	if q.Get("ssl-ca") != "" {
		return ""
	}
	switch mode := strings.ToLower(q.Get("tls")); mode {
	case "", "false":
		return "its connection URL sets no tls, so the password crosses the network in the clear; set tls=true (and ssl-ca=/path for a private CA)"
	case "preferred":
		return "its connection URL sets tls=preferred, which falls back to plaintext and checks no certificate; set tls=true"
	case "skip-verify":
		return "its connection URL sets tls=skip-verify, which checks no certificate; set tls=true (and ssl-ca=/path for a private CA)"
	}
	return ""
}

// allLoopback is whether every host names this machine: empty (a Unix
// socket), a socket directory, localhost, or a loopback address.
func allLoopback(hosts []string) bool {
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if host, _, err := net.SplitHostPort(h); err == nil {
			h = host
		}
		h = strings.Trim(h, "[]")
		switch {
		case h == "", strings.HasPrefix(h, "/"), strings.EqualFold(h, "localhost"):
			continue
		}
		if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
			continue
		}
		return false
	}
	return true
}

// saidTLS remembers what was said: doctor resolves a surface's URL once per
// check, and printed the same warning three times before its table.
var saidTLS sync.Map

// sayDatabaseTLS prints the warning for one surface to stderr, once a run.
func sayDatabaseTLS(who, raw string) {
	if w := databaseTLSWarning(raw); w != "" {
		line := fmt.Sprintf("Warning: %s: %s.\n", who, w)
		if _, said := saidTLS.LoadOrStore(line, true); !said {
			fmt.Fprint(os.Stderr, line)
		}
	}
}
