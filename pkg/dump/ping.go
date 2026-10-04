package dump

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

// Dialer opens the network connection a database driver asks for. A caller
// passes one to refuse addresses it must not reach; nil dials as the driver
// does.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// PingDatabase opens the database a connection string names, as a backup
// would, runs the cheapest query the engine has, and returns the server's own
// words when it cannot: a refused password, an unknown database, a host that
// does not answer. It stops at the context's deadline.
func PingDatabase(ctx context.Context, databaseURL string, dial Dialer) error {
	switch {
	case IsSQLiteURL(databaseURL):
		return PingSQLite(ctx, databaseURL)
	case IsMongoURL(databaseURL):
		return pingMongo(ctx, databaseURL, dial)
	case IsMySQLURL(databaseURL):
		return pingMySQL(ctx, databaseURL, dial)
	}
	return pingPostgres(ctx, databaseURL, dial)
}

func pingPostgres(ctx context.Context, databaseURL string, dial Dialer) error {
	cfg, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		return err
	}
	if dial != nil {
		cfg.DialFunc = pgconn.DialFunc(dial)
	}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		// The driver's text repeats the user and database before the
		// reason; the reason alone is what the person typing the string
		// needs.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			return errors.New(pgErr.Message)
		}
		var ce *pgconn.ConnectError
		if errors.As(err, &ce) && ce.Unwrap() != nil {
			return ce.Unwrap()
		}
		return err
	}
	defer conn.Close(ctx)
	var one int
	return conn.QueryRow(ctx, "SELECT 1").Scan(&one)
}

func pingMySQL(ctx context.Context, databaseURL string, dial Dialer) error {
	t, err := parseMySQLURL(databaseURL)
	if err != nil {
		return err
	}
	cfg, err := t.driverConfig()
	if err != nil {
		return err
	}
	if dial != nil {
		cfg.DialFunc = dial
	}
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		return err
	}
	db := sql.OpenDB(connector)
	defer db.Close()
	return db.PingContext(ctx)
}

// contextDialer adapts a Dialer to the MongoDB driver's interface.
type contextDialer Dialer

func (d contextDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d(ctx, network, addr)
}

func pingMongo(ctx context.Context, databaseURL string, dial Dialer) error {
	timeout := 15 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		if left := time.Until(dl); left < timeout {
			timeout = left
		}
	}
	opts := options.Client().ApplyURI(databaseURL).SetServerSelectionTimeout(timeout).SetConnectTimeout(timeout)
	if dial != nil {
		opts.SetDialer(contextDialer(dial))
	}
	client, err := mongo.Connect(opts)
	if err != nil {
		return fmt.Errorf("mongodb: %w", err)
	}
	defer func() { _ = client.Disconnect(context.Background()) }()
	return client.Ping(ctx, readpref.Primary())
}
