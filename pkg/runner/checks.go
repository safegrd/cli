package runner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/model"
)

const (
	defaultSQLCheckTimeout     = 60 * time.Second
	defaultCommandCheckTimeout = 5 * time.Minute
	// checkOutputLimit is how much of a failed command's output the report
	// carries: its last lines, which is where a test runner says what failed.
	checkOutputLimit = 1000
)

// runChecks runs the customer's drill checks against the restored sandbox and
// appends one assertion per check to the report. It returns the names of the
// checks that failed.
func (v *Verifier) runChecks(ctx context.Context, report *model.VerificationReport, sandboxURL string) []string {
	if len(v.Checks) == 0 {
		return nil
	}
	// A check that cannot run is a failed check, said in its own words, so a
	// typo in one does not make the drill pass without it.
	if err := model.ValidateDrillChecks(v.Checks); err != nil {
		report.Assertions = append(report.Assertions, model.AssertionResult{
			Name: "DrillChecks", Kind: model.AssertionKindCheck, Passed: false,
			Expected: fmt.Sprintf("%d checks that can run", len(v.Checks)), Actual: err.Error(), Message: err.Error(),
		})
		return []string{"DrillChecks"}
	}
	var failed []string
	for _, c := range v.Checks {
		var a model.AssertionResult
		if strings.TrimSpace(c.Command) != "" {
			a = runCommandCheck(ctx, c, sandboxURL, report)
		} else {
			a = runSQLCheck(ctx, c, sandboxURL)
		}
		a.Name, a.Kind = strings.TrimSpace(c.Name), model.AssertionKindCheck
		if !a.Passed {
			failed = append(failed, a.Name)
		}
		report.Assertions = append(report.Assertions, a)
	}
	return failed
}

// drillFailureMessage is the report's error for a sandbox drill that failed:
// whether the restore itself matched the backup, and which of the
// customer's checks did not hold.
func drillFailureMessage(structuralPassed bool, failedChecks []string, totalChecks int) string {
	if structuralPassed && len(failedChecks) > 0 {
		return fmt.Sprintf("The restore matched the backup, and %d of %d drill checks failed: %s",
			len(failedChecks), totalChecks, strings.Join(failedChecks, ", "))
	}
	if len(failedChecks) > 0 {
		return fmt.Sprintf("One or more integrity assertions failed during Fire Drill, and %d of %d drill checks failed: %s",
			len(failedChecks), totalChecks, strings.Join(failedChecks, ", "))
	}
	return "One or more integrity assertions failed during Fire Drill"
}

func checkTimeout(c model.DrillCheck, def time.Duration) time.Duration {
	if c.TimeoutSeconds > 0 {
		return time.Duration(c.TimeoutSeconds) * time.Second
	}
	return def
}

// runSQLCheck runs the check's query in a read-only transaction and holds the
// first column of its first row to the expected value.
func runSQLCheck(ctx context.Context, c model.DrillCheck, sandboxURL string) model.AssertionResult {
	want, _ := model.ParseDrillExpect(c.Expect) // validated by runChecks
	a := model.AssertionResult{Expected: want.String()}
	timeout := checkTimeout(c, defaultSQLCheckTimeout)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	got, err := querySandboxValue(ctx, sandboxURL, c.SQL, timeout)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			err = fmt.Errorf("did not finish within %s", timeout)
		}
		a.Actual = "error"
		a.Message = "The query failed: " + err.Error()
		return a
	}
	a.Actual = got
	a.Passed = want.Holds(got)
	if !a.Passed {
		a.Message = fmt.Sprintf("The query returned %s, expected %s", got, want)
	}
	return a
}

// errNoRows is a check query that returned nothing to compare.
var errNoRows = errors.New("it returned no rows")

// querySandboxValue returns the first column of the first row as text, with
// NULL as "NULL".
func querySandboxValue(ctx context.Context, sandboxURL, query string, timeout time.Duration) (string, error) {
	switch {
	case dump.IsMongoURL(sandboxURL):
		return "", errors.New("a MongoDB sandbox takes no SQL; write this check as a command")
	case dump.IsSQLiteURL(sandboxURL):
		path, err := dump.SQLitePath(sandboxURL)
		if err != nil {
			return "", err
		}
		// mode=ro: the check reads the restored file and never writes it.
		dsn := (&url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro"}).String()
		db, err := sql.Open("sqlite", dsn)
		if err != nil {
			return "", err
		}
		defer db.Close()
		return firstSQLValue(ctx, db, query, nil)
	case dump.IsMySQLURL(sandboxURL):
		db, err := dump.OpenMySQL(sandboxURL)
		if err != nil {
			return "", err
		}
		defer db.Close()
		return firstSQLValue(ctx, db, query, &sql.TxOptions{ReadOnly: true})
	}
	conn, err := pgx.Connect(ctx, sandboxURL)
	if err != nil {
		return "", fmt.Errorf("cannot connect to the sandbox: %w", err)
	}
	defer conn.Close(context.Background())
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(context.Background()) }() // read-only: nothing to keep
	if _, err := tx.Exec(ctx, "SET LOCAL statement_timeout = "+strconv.FormatInt(timeout.Milliseconds(), 10)); err != nil {
		return "", err
	}
	rows, err := tx.Query(ctx, query)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return "", err
		}
		return "", errNoRows
	}
	vals, err := rows.Values()
	if err != nil {
		return "", err
	}
	if len(vals) == 0 {
		return "", errors.New("it returned no columns")
	}
	return checkValueText(vals[0]), nil
}

func firstSQLValue(ctx context.Context, db *sql.DB, query string, opts *sql.TxOptions) (string, error) {
	tx, err := db.BeginTx(ctx, opts)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }() // read-only: nothing to keep
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return "", err
		}
		return "", errNoRows
	}
	cols, err := rows.Columns()
	if err != nil {
		return "", err
	}
	if len(cols) == 0 {
		return "", errors.New("it returned no columns")
	}
	dest := make([]any, len(cols))
	var first any
	dest[0] = &first
	for i := 1; i < len(dest); i++ {
		dest[i] = new(any)
	}
	if err := rows.Scan(dest...); err != nil {
		return "", err
	}
	return checkValueText(first), nil
}

// checkValueText renders a scanned value the way the expectation compares it.
func checkValueText(v any) string {
	switch x := v.(type) {
	case nil:
		return "NULL"
	case []byte:
		return string(x)
	case time.Time:
		return x.UTC().Format(time.RFC3339Nano)
	case [16]byte: // pgx's uuid
		return fmt.Sprintf("%x-%x-%x-%x-%x", x[0:4], x[4:6], x[6:8], x[8:10], x[10:16])
	case fmt.Stringer:
		return x.String()
	}
	// pgx returns numeric as pgtype.Numeric, which prints as a struct; its
	// driver value is the number as PostgreSQL writes it.
	if tv, ok := v.(driver.Valuer); ok {
		if inner, err := tv.Value(); err == nil && inner != nil {
			return checkValueText(inner)
		}
	}
	return fmt.Sprint(v)
}

// runCommandCheck runs the check's command through sh -c, with the
// sandbox's connection string in SAFEGRD_SANDBOX_URL. Exit 0 passes.
func runCommandCheck(ctx context.Context, c model.DrillCheck, sandboxURL string, report *model.VerificationReport) model.AssertionResult {
	a := model.AssertionResult{Expected: "exit 0"}
	timeout := checkTimeout(c, defaultCommandCheckTimeout)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-c", c.Command)
	cmd.Env = append(os.Environ(),
		"SAFEGRD_SANDBOX_URL="+sandboxURL,
		"SAFEGRD_SNAPSHOT_ID="+report.SnapshotID,
		"SAFEGRD_DATABASE_NAME="+report.DatabaseName,
	)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	// A command that leaves a child holding its output open must not hold
	// the drill past its timeout.
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	tail := redactSandbox(lastBytes(out.String(), checkOutputLimit), sandboxURL)
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		a.Passed, a.Actual = true, "exit 0"
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		a.Actual = "timed out"
		a.Message = fmt.Sprintf("The command did not finish within %s", timeout)
	case errors.As(err, &exitErr):
		a.Actual = fmt.Sprintf("exit %d", exitErr.ExitCode())
		a.Message = fmt.Sprintf("The command exited %d", exitErr.ExitCode())
	default:
		a.Actual = "did not start"
		a.Message = "The command did not start: " + err.Error()
	}
	if !a.Passed && tail != "" {
		a.Message += ": " + tail
	}
	return a
}

func lastBytes(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	cut := s[len(s)-n:]
	if i := strings.IndexByte(cut, '\n'); i >= 0 && i < len(cut)-1 {
		cut = cut[i+1:]
	}
	return "..." + cut
}

// redactSandbox keeps the sandbox's password out of what a command printed,
// since the report leaves this host.
func redactSandbox(s, sandboxURL string) string {
	if s == "" {
		return s
	}
	if u, err := url.Parse(sandboxURL); err == nil && u.User != nil {
		if pw, ok := u.User.Password(); ok && pw != "" {
			s = strings.ReplaceAll(s, pw, "REDACTED")
		}
	}
	return s
}

// checksDigest is the SHA-256 of the customer's check results, which the
// certificate hash covers, so a check's result cannot change after the
// record is signed. Empty when the drill ran no checks.
func checksDigest(r *model.VerificationReport) string {
	var b strings.Builder
	for _, a := range r.Assertions {
		if a.Kind != model.AssertionKindCheck {
			continue
		}
		fmt.Fprintf(&b, "%s|%t|%s|%s\n", a.Name, a.Passed, a.Expected, a.Actual)
	}
	if b.Len() == 0 {
		return ""
	}
	h := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(h[:])
}
