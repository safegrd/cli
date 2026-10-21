package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/model"
)

// A drill that loads a sandbox has the database check what it loaded, not
// only count it: rows can come back in the right number over a heap page or
// an index the database cannot read. Each engine's own check is one
// assertion of Kind data; one the sandbox cannot run is recorded as not
// run, which neither passes nor fails the drill.

// dataCheck runs the engine's check of the data in the sandbox.
func dataCheck(ctx context.Context, kind model.SurfaceType, sandboxURL string) model.AssertionResult {
	switch {
	case dump.IsSQLiteURL(sandboxURL):
		// The SQLite restorer already ran PRAGMA integrity_check.
		return model.AssertionResult{}
	case dump.IsMongoURL(sandboxURL):
		return mongoValidate(ctx, sandboxURL)
	case dump.IsMySQLURL(sandboxURL):
		return mysqlCheckTable(ctx, sandboxURL)
	}
	return postgresAmcheck(ctx, sandboxURL)
}

func notRun(name, expected, why string) model.AssertionResult {
	return model.AssertionResult{Name: name, Kind: model.AssertionKindData, NotRun: true, Expected: expected, Actual: "not run", Message: why}
}

func someNames(names []string) string {
	sort.Strings(names)
	if len(names) > 5 {
		return strings.Join(names[:5], ", ") + fmt.Sprintf(" and %d more", len(names)-5)
	}
	return strings.Join(names, ", ")
}

// postgresAmcheck checks every table's heap with verify_heapam
// (PostgreSQL 14 and later) and every B-tree index with bt_index_check.
// amcheck ships with PostgreSQL's contrib; a sandbox without it, or a role
// that may not create it, records the check as not run.
func postgresAmcheck(ctx context.Context, sandboxURL string) model.AssertionResult {
	const name, expected = "Data Check: amcheck", "every heap and B-tree index readable"
	conn, err := pgx.Connect(ctx, sandboxURL)
	if err != nil {
		return notRun(name, expected, "connecting to the sandbox: "+err.Error())
	}
	defer conn.Close(context.Background())
	simple := pgx.QueryExecModeSimpleProtocol
	var schema string
	created := false
	if err := conn.QueryRow(ctx, "SELECT n.nspname FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace WHERE e.extname = 'amcheck'", simple).Scan(&schema); err != nil {
		var available bool
		if err := conn.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'amcheck')", simple).Scan(&available); err != nil || !available {
			return notRun(name, expected, "the sandbox's PostgreSQL has no amcheck extension (it ships in contrib)")
		}
		if _, err := conn.Exec(ctx, "CREATE SCHEMA safegrd_amcheck; CREATE EXTENSION amcheck SCHEMA safegrd_amcheck", simple); err != nil {
			return notRun(name, expected, "the sandbox role may not create the amcheck extension: "+err.Error())
		}
		created = true
		// Some servers place an extension where they choose (Supabase puts
		// every extension in its extensions schema): read where it went.
		if err := conn.QueryRow(ctx, "SELECT n.nspname FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace WHERE e.extname = 'amcheck'", simple).Scan(&schema); err != nil {
			return notRun(name, expected, "amcheck was created and cannot be found: "+err.Error())
		}
	}
	if created {
		defer func() {
			// The sandbox is reset after the drill either way.
			_, _ = conn.Exec(context.Background(), "DROP EXTENSION IF EXISTS amcheck; DROP SCHEMA IF EXISTS safegrd_amcheck CASCADE", simple)
		}()
	}
	q := pgx.Identifier{schema}.Sanitize()
	var hasHeap bool
	_ = conn.QueryRow(ctx, "SELECT to_regproc($1) IS NOT NULL", q+".verify_heapam").Scan(&hasHeap)

	var bad []string
	tables, indexes := 0, 0
	if hasHeap {
		rows, err := conn.Query(ctx, `SELECT c.oid, quote_ident(n.nspname) || '.' || quote_ident(c.relname) FROM pg_class c
			JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE c.relkind IN ('r', 'm') AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'safegrd_amcheck') AND n.nspname NOT LIKE 'pg_toast%'`)
		if err != nil {
			return notRun(name, expected, "listing the sandbox's tables: "+err.Error())
		}
		type rel struct {
			oid  uint32
			name string
		}
		var rels []rel
		for rows.Next() {
			var r rel
			if rows.Scan(&r.oid, &r.name) == nil {
				rels = append(rels, r)
			}
		}
		rows.Close()
		for _, r := range rels {
			var n int64
			if err := conn.QueryRow(ctx, "SELECT count(*) FROM "+q+".verify_heapam($1::oid::regclass)", r.oid).Scan(&n); err != nil {
				if !pgCorrupt(err) {
					return notRun(name, expected, "amcheck could not run: "+err.Error())
				}
				bad = append(bad, r.name+" ("+err.Error()+")")
			} else if n > 0 {
				bad = append(bad, fmt.Sprintf("%s (%d problems)", r.name, n))
			}
			tables++
		}
	}
	rows, err := conn.Query(ctx, `SELECT c.oid, quote_ident(n.nspname) || '.' || quote_ident(c.relname) FROM pg_index i
		JOIN pg_class c ON c.oid = i.indexrelid JOIN pg_namespace n ON n.oid = c.relnamespace JOIN pg_am am ON am.oid = c.relam
		WHERE am.amname = 'btree' AND i.indisvalid AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'safegrd_amcheck') AND n.nspname NOT LIKE 'pg_toast%'`)
	if err != nil {
		return notRun(name, expected, "listing the sandbox's indexes: "+err.Error())
	}
	type rel struct {
		oid  uint32
		name string
	}
	var idx []rel
	for rows.Next() {
		var r rel
		if rows.Scan(&r.oid, &r.name) == nil {
			idx = append(idx, r)
		}
	}
	rows.Close()
	for _, r := range idx {
		if _, err := conn.Exec(ctx, "SELECT "+q+".bt_index_check($1::oid::regclass)", r.oid); err != nil {
			if !pgCorrupt(err) {
				return notRun(name, expected, "amcheck could not run: "+err.Error())
			}
			bad = append(bad, r.name+" ("+err.Error()+")")
		}
		indexes++
	}
	checked := fmt.Sprintf("%d tables, %d B-tree indexes", tables, indexes)
	if !hasHeap {
		checked = fmt.Sprintf("%d B-tree indexes (verify_heapam needs PostgreSQL 14)", indexes)
	}
	a := model.AssertionResult{Name: name, Kind: model.AssertionKindData, Expected: expected, Passed: len(bad) == 0}
	if a.Passed {
		a.Actual = checked + ", no corruption"
	} else {
		a.Actual = checked + ", corruption in " + someNames(bad)
		a.Message = "amcheck found pages or index entries in the restored data that PostgreSQL cannot read"
	}
	return a
}

// mysqlCheckTable runs CHECK TABLE over every base table restored.
func mysqlCheckTable(ctx context.Context, sandboxURL string) model.AssertionResult {
	const name, expected = "Data Check: CHECK TABLE", "every table OK"
	db, err := dump.OpenMySQL(sandboxURL)
	if err != nil {
		return notRun(name, expected, "connecting to the sandbox: "+err.Error())
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx, "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE'")
	if err != nil {
		return notRun(name, expected, "listing the sandbox's tables: "+err.Error())
	}
	var tables []string
	for rows.Next() {
		var t string
		if rows.Scan(&t) == nil {
			tables = append(tables, t)
		}
	}
	rows.Close()
	var bad []string
	for _, t := range tables {
		res, err := db.QueryContext(ctx, "CHECK TABLE `"+strings.ReplaceAll(t, "`", "``")+"`")
		if err != nil {
			if strings.Contains(err.Error(), "Error 1142") {
				return notRun(name, expected, "the sandbox user may not run CHECK TABLE: "+err.Error())
			}
			bad = append(bad, t+" ("+err.Error()+")")
			continue
		}
		ok := false
		var problems []string
		for res.Next() {
			var table, op, msgType, msgText string
			if res.Scan(&table, &op, &msgType, &msgText) != nil {
				continue
			}
			switch {
			case msgType == "status" && strings.EqualFold(msgText, "OK"):
				ok = true
			case msgType == "error" || (msgType == "status" && !strings.EqualFold(msgText, "OK")):
				problems = append(problems, msgText)
			}
		}
		res.Close()
		if !ok || len(problems) > 0 {
			bad = append(bad, t+" ("+strings.Join(problems, "; ")+")")
		}
	}
	a := model.AssertionResult{Name: name, Kind: model.AssertionKindData, Expected: expected, Passed: len(bad) == 0}
	if a.Passed {
		a.Actual = fmt.Sprintf("%d tables OK", len(tables))
	} else {
		a.Actual = "not OK: " + someNames(bad)
		a.Message = "CHECK TABLE found restored tables MySQL cannot read cleanly"
	}
	return a
}

// mongoValidate runs validate on every collection restored.
func mongoValidate(ctx context.Context, sandboxURL string) model.AssertionResult {
	const name, expected = "Data Check: validate", "every collection valid"
	client, db, err := dump.OpenMongo(ctx, sandboxURL)
	if err != nil {
		return notRun(name, expected, "connecting to the sandbox: "+err.Error())
	}
	defer func() { _ = client.Disconnect(context.Background()) }()
	names, err := db.ListCollectionNames(ctx, bson.D{{Key: "type", Value: "collection"}})
	if err != nil {
		return notRun(name, expected, "listing the sandbox's collections: "+err.Error())
	}
	var bad []string
	checked := 0
	for _, c := range names {
		if strings.HasPrefix(c, "system.") {
			continue
		}
		var res struct {
			Valid  bool     `bson:"valid"`
			Errors []string `bson:"errors"`
		}
		if err := db.RunCommand(ctx, bson.D{{Key: "validate", Value: c}}).Decode(&res); err != nil {
			var ce mongo.CommandError
			if errors.As(err, &ce) && ce.Code == 13 {
				return notRun(name, expected, "the sandbox user may not run validate; it needs dbAdmin on the sandbox database")
			}
			bad = append(bad, c+" ("+err.Error()+")")
			continue
		}
		checked++
		if !res.Valid {
			bad = append(bad, c+" ("+strings.Join(res.Errors, "; ")+")")
		}
	}
	a := model.AssertionResult{Name: name, Kind: model.AssertionKindData, Expected: expected, Passed: len(bad) == 0}
	if a.Passed {
		a.Actual = fmt.Sprintf("%d collections valid", checked)
	} else {
		a.Actual = "not valid: " + someNames(bad)
		a.Message = "validate found restored collections MongoDB reports as damaged"
	}
	return a
}

// pgCorrupt is amcheck's error for data it found damaged: data_corrupted
// (XX001) or index_corrupted (XX002). Anything else (a privilege, a function
// the server does not have) is amcheck not running, not the data failing.
func pgCorrupt(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && (pe.Code == "XX001" || pe.Code == "XX002")
}

// dataChecksDigest is the SHA-256 of the data checks' results, which the
// certificate hash covers, so it says which checks ran and what they found.
func dataChecksDigest(r *model.VerificationReport) string {
	var b strings.Builder
	for _, a := range r.Assertions {
		if a.Kind != model.AssertionKindData {
			continue
		}
		fmt.Fprintf(&b, "%s|%t|%t|%s\n", a.Name, a.Passed, a.NotRun, a.Actual)
	}
	if b.Len() == 0 {
		return ""
	}
	h := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(h[:])
}
