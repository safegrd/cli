package dump

import (
	"crypto/x509"
	"errors"
	"strings"
	"testing"
)

// mongodump's connection error repeats the connection string, password
// included, on a timestamped line after the CLI's own. The message has to
// carry the reason on one line and never the password.
func TestToolMessageKeepsTheReasonAndDropsThePassword(t *testing.T) {
	stderr := "2026-10-05T16:45:51.362+0000\tFailed: can't create session: failed to connect to " +
		"mongodb+srv://safegrd:s3cret-pw@cluster0.example.mongodb.net/shop_events: connection() error occurred " +
		"during connection handshake: auth error: sasl conversation error: unable to authenticate using mechanism \"SCRAM-SHA-1\": (AtlasError) bad auth : authentication failed\n"
	got := toolMessage(stderr)
	if strings.Contains(got, "s3cret-pw") {
		t.Fatalf("the password is in the message: %q", got)
	}
	if strings.Contains(got, "\n") || strings.HasPrefix(got, "2026-") {
		t.Fatalf("the message is not one line without the log stamp: %q", got)
	}
	for _, want := range []string{"Failed: can't create session", "bad auth", "mongodb+srv://safegrd:xxxxx@cluster0.example.mongodb.net"} {
		if !strings.Contains(got, want) {
			t.Errorf("the message lacks %q: %q", want, got)
		}
	}
	if got := toolMessage("mysqldump: Got error: 1045: Access denied\nsecond line\n"); got != "mysqldump: Got error: 1045: Access denied; second line" {
		t.Errorf("two lines became %q", got)
	}
	if got := toolMessage("connecting to postgres://u@h/db?password=hunter2&sslmode=require"); strings.Contains(got, "hunter2") {
		t.Errorf("a query password survived: %q", got)
	}
}

// tls=true checks the server's certificate, and a stock MySQL's is
// self-signed, so the connection failed with only the x509 error and no way
// on. The error names both ways on.
func TestAnUnverifiedMySQLCertificateSaysWhatToDo(t *testing.T) {
	err := mysqlTLSAdvice(x509.HostnameError{Certificate: &x509.Certificate{}, Host: "bore.pub"})
	for _, want := range []string{"certificate is not valid", "ssl-ca=/path/ca.pem", "tls=skip-verify"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error lacks %q: %v", want, err)
		}
	}
	if !errors.As(err, new(x509.HostnameError)) {
		t.Error("the advice hid the x509 error from errors.As")
	}
	other := errors.New("Access denied for user 'omar'")
	if got := mysqlTLSAdvice(other); got != other {
		t.Errorf("an unrelated error changed: %v", got)
	}
}
