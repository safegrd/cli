package dump

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/jackc/pgx/v5/pgconn"
)

var invalidPageRe = regexp.MustCompile(`invalid page in block (\d+) of relation (\S+)`)

// damagedPage puts PostgreSQL's "invalid page in block N of relation
// base/..." into words that name the table: a page of it is damaged on
// disk, and the read through the buffer cache stopped there. nil for any
// other error.
func damagedPage(schema, table string, err error) error {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "XX001" {
		return nil
	}
	m := invalidPageRe.FindStringSubmatch(pgErr.Message)
	if m == nil {
		return nil
	}
	return fmt.Errorf("table %s.%s is damaged on disk: block %s of its file %s failed PostgreSQL's page check, so the table cannot be read and this backup stopped. "+
		"Restore the table from an earlier backup or repair it, then back up again", schema, table, m[1], m[2])
}
