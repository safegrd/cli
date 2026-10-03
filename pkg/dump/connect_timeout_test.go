package dump

import (
	"context"
	"net"
	"testing"
	"time"
)

// A database that accepts the connection and then says nothing must fail the
// backup, not hold it open: before connectPostgres a paused source held one
// past five minutes. The default applies when the URL sets none, and the URL
// wins.
func TestConnectingToASilentDatabaseTimesOut(t *testing.T) {
	cfg, err := postgresConnConfig("postgres://u:p@localhost:5432/db")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ConnectTimeout != defaultConnectTimeout {
		t.Errorf("ConnectTimeout = %v, want the default %v", cfg.ConnectTimeout, defaultConnectTimeout)
	}
	cfg, err = postgresConnConfig("postgres://u:p@localhost:5432/db?connect_timeout=5")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ConnectTimeout != 5*time.Second {
		t.Errorf("ConnectTimeout = %v, want the URL's 5s", cfg.ConnectTimeout)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close() // accept, then never answer
		}
	}()
	start := time.Now()
	_, err = connectPostgres(context.Background(), "postgres://u:p@"+ln.Addr().String()+"/db?sslmode=disable&connect_timeout=1")
	if err == nil {
		t.Fatal("connecting to a database that never answers succeeded")
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Errorf("connecting to a silent database took %v", took)
	}
}
