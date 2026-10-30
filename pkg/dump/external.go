package dump

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// What a backup another tool made holds, and how it is loaded. A plain
// mysqldump file and a mongodump archive are read and loaded here with the
// same code SafeGrd's own snapshots go through, without the archive and
// manifest a snapshot wraps them in.

// MySQLDumpContents is what a plain mysqldump or mariadb-dump file holds.
type MySQLDumpContents struct {
	// Tables in the order the dump creates them, with each one's rows. A
	// dump of several databases (--databases, --all-databases) names them
	// database.table.
	Tables []string
	Rows   map[string]int64
	// Completed is set when the dump ends with its completion line; a dump
	// that stopped part way does not, however cleanly its process exited.
	Completed bool
	// Database and ServerVersion are what the dump's header says, when it
	// has one.
	Database, ServerVersion string
	// CreatesDatabase is set when the dump creates or switches databases:
	// loading it would leave the target database.
	CreatesDatabase bool
}

// CountMySQLDump reads a plain SQL dump to its end and counts each table's
// rows from its INSERT statements.
func CountMySQLDump(r io.Reader) (*MySQLDumpContents, error) {
	counter := newMySQLDumpCounter()
	if _, err := io.Copy(counter, r); err != nil {
		return nil, err
	}
	return &MySQLDumpContents{Tables: counter.Tables(), Rows: counter.Rows, Completed: counter.Completed,
		Database: counter.Database, ServerVersion: counter.ServerVersion, CreatesDatabase: counter.CreatesDatabase}, nil
}

// LoadMySQLDump pipes a plain SQL dump into the database targetURL names
// through the server's own client, every DEFINER in it set to the loading
// account. The client stops at the first error; MySQL commits DDL as it
// goes, so a failure can leave part of the dump behind, and the error says
// so.
func LoadMySQLDump(ctx context.Context, targetURL string, src io.Reader) error {
	target, err := parseMySQLURL(targetURL)
	if err != nil {
		return err
	}
	db, err := target.open()
	if err != nil {
		return err
	}
	defer db.Close()
	_, mariaDB, err := mysqlServer(ctx, db)
	if err != nil {
		return fmt.Errorf("could not connect to the sandbox database: %w", err)
	}
	tool, err := findMySQLTool(ctx, "client", mariaDB)
	if err != nil {
		return err
	}
	cnf, cleanup, err := target.defaultsFile()
	if err != nil {
		return err
	}
	defer cleanup()
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, tool.Path, "--defaults-extra-file="+cnf,
		"--binary-mode", "--default-character-set=utf8mb4", "--database="+target.Database)
	cmd.Stdin = newDefinerRewriter(src)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := toolMessage(stderr.String())
		if len(msg) > 500 {
			msg = msg[:500] + "..."
		}
		return fmt.Errorf("%s failed: %v: %s. The sandbox may now hold part of the dump", tool, err, msg)
	}
	return nil
}

// MongoArchiveContents is what a mongodump archive holds.
type MongoArchiveContents struct {
	ServerVersion string
	// Collections as database.collection, in the archive's order, each with
	// its documents. Views are left out: a view holds no documents.
	Collections []string
	Docs        map[string]int64
	// Unfinished names the namespaces whose end never came: the archive was
	// cut short. CRCFailed names those whose documents do not match the CRC
	// mongodump wrote.
	Unfinished, CRCFailed []string
}

// Databases lists the databases the archive holds.
func (c *MongoArchiveContents) Databases() []string {
	var out []string
	seen := map[string]bool{}
	for _, ns := range c.Collections {
		db, _, _ := strings.Cut(ns, ".")
		if !seen[db] {
			seen[db] = true
			out = append(out, db)
		}
	}
	return out
}

// ReadMongoArchive reads a plain (not gzipped) mongodump archive to its end.
func ReadMongoArchive(r io.Reader) (*MongoArchiveContents, error) {
	st, err := readMongoArchive(r, nil)
	if err != nil {
		return nil, err
	}
	return &MongoArchiveContents{ServerVersion: st.ServerVersion, Collections: st.Collections, Docs: st.Docs,
		Unfinished: st.missingEnds(), CRCFailed: st.CRCFailed}, nil
}

// LoadMongoArchive pipes a plain mongodump archive of one database into the
// database targetURL names, through mongorestore, renaming the archive's
// database to the target's. mongorestore writes as it goes, so a failure
// part way leaves part of the archive behind, and the error says so.
func LoadMongoArchive(ctx context.Context, targetURL string, src io.Reader) error {
	targetDB, err := mongoDatabase(targetURL)
	if err != nil {
		return err
	}
	tool, err := findMongoTool(ctx, "mongorestore")
	if err != nil {
		return err
	}
	cfgPath, cleanup, err := mongoToolConfig(withoutDatabase(targetURL))
	if err != nil {
		return err
	}
	defer cleanup()
	br := bufio.NewReaderSize(src, 1<<20)
	sourceDB, err := peekMongoDatabase(br)
	if err != nil {
		return err
	}
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, tool.Path, "--config="+cfgPath, "--archive", "--stopOnError",
		"--nsFrom="+sourceDB+".*", "--nsTo="+targetDB+".*")
	cmd.Stdin = br
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := toolMessage(stderr.String())
		if len(msg) > 500 {
			msg = msg[:500] + "..."
		}
		return fmt.Errorf("%s failed: %v: %s. The sandbox may now hold part of the archive", tool, err, msg)
	}
	return nil
}
