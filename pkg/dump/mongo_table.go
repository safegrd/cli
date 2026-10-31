package dump

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os/exec"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/safegrd/cli/pkg/model"
)

// MongoPreludeFor is a run's prelude narrowed to the named collections: the
// archive header, then those namespaces' metadata documents (options and
// indexes) in the order the prelude has them. A chosen collection the
// prelude does not name is restored with no options and no indexes, as the
// run holds none for it.
func MongoPreludeFor(prelude []byte, collections map[string]bool) ([]byte, error) {
	var out bytes.Buffer
	rest := prelude
	first := true
	for len(rest) > 0 {
		if len(rest) < 4 {
			return nil, fmt.Errorf("the run's prelude ends inside a document")
		}
		n := int(int32(binary.LittleEndian.Uint32(rest[:4])))
		if n < 5 || n > len(rest) {
			return nil, fmt.Errorf("the run's prelude holds a document of %d bytes", n)
		}
		d := bson.Raw(rest[:n])
		rest = rest[n:]
		if first {
			out.Write(d)
			first = false
			continue
		}
		coll, _ := d.Lookup("collection").StringValueOK()
		if collections[coll] {
			out.Write(d)
		}
	}
	if first {
		return nil, fmt.Errorf("the run's prelude has no header")
	}
	return out.Bytes(), nil
}

// RestoreMongoCollections loads chosen collections of a run into a database
// that may hold others. The archive mongorestore reads is built from the
// prelude's entries for those collections alone and their documents, so
// nothing else is created in the target. Before anything is written each
// chosen collection is checked in the target: absent, or empty. After,
// each one's documents are counted against the manifest. mongorestore
// writes as it goes, so a failure part way leaves what loaded in the
// target, which the error says. created names the collections the target
// lacked.
func RestoreMongoCollections(ctx context.Context, targetURL string, prelude []byte, parts []MongoRunPart, stats []model.TableStat, parallel int) (created []string, docs int64, err error) {
	if len(parts) != len(stats) {
		return nil, 0, fmt.Errorf("each collection needs its manifest entry")
	}
	targetDB, err := mongoDatabase(targetURL)
	if err != nil {
		return nil, 0, err
	}
	client, db, err := OpenMongo(ctx, targetURL)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = client.Disconnect(context.Background()) }()
	chosen := map[string]bool{}
	for i, p := range parts {
		chosen[p.Collection] = true
		names, err := db.ListCollectionNames(ctx, bson.D{{Key: "name", Value: p.Collection}})
		if err != nil {
			return nil, 0, fmt.Errorf("could not inspect the target database: %w", err)
		}
		if len(names) == 0 {
			created = append(created, p.Collection)
			continue
		}
		counts, err := MongoCountDocuments(ctx, db, &model.SnapshotMetadata{TableStats: stats[i : i+1]})
		if err != nil {
			return nil, 0, err
		}
		if counts[p.Collection] > 0 {
			return nil, 0, fmt.Errorf("%s in the target holds documents; a restore never writes over data. Empty it, or restore into another database", p.Collection)
		}
	}
	_, nss, err := mongoPreludeNamespaces(prelude)
	if err != nil {
		return nil, 0, err
	}
	if len(nss) == 0 {
		return nil, 0, fmt.Errorf("the run's prelude names no database")
	}
	sourceDB := nss[0].db
	narrowed, err := MongoPreludeFor(prelude, chosen)
	if err != nil {
		return nil, 0, err
	}
	tool, err := findMongoTool(ctx, "mongorestore")
	if err != nil {
		return nil, 0, err
	}
	// As a whole restore: the target is given by --nsTo, and the URI keeps
	// only where to connect and which database to authenticate against.
	cfgPath, cleanup, err := mongoToolConfig(withoutDatabase(targetURL))
	if err != nil {
		return nil, 0, err
	}
	defer cleanup()
	pr, pw := io.Pipe()
	built := make(chan error, 1)
	go func() {
		err := WriteMongoRunArchive(narrowed, parts, pw)
		_ = pw.CloseWithError(err)
		built <- err
	}()
	args := []string{"--config=" + cfgPath, "--archive", "--stopOnError", "--nsFrom=" + sourceDB + ".*", "--nsTo=" + targetDB + ".*"}
	if parallel > 1 {
		args = append(args, fmt.Sprintf("--numInsertionWorkersPerCollection=%d", parallel))
	}
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, tool.Path, args...)
	cmd.Stdin = pr
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	_, _ = io.Copy(io.Discard, pr) // what the tool did not read
	_ = pr.Close()
	if berr := <-built; berr != nil && runErr == nil {
		runErr = berr
	}
	if runErr != nil {
		msg := toolMessage(stderr.String())
		if len(msg) > 500 {
			msg = msg[:500] + "..."
		}
		what := "it"
		if len(parts) > 1 {
			what = "them"
		}
		return nil, 0, fmt.Errorf("%s failed: %v: %s. The target may now hold part of the chosen %s; drop %s before retrying",
			tool, runErr, msg, plural(len(parts), "collection", "collections"), what)
	}
	counts, err := MongoCountDocuments(ctx, db, &model.SnapshotMetadata{TableStats: stats})
	if err != nil {
		return nil, 0, err
	}
	for _, t := range stats {
		if counts[t.TableName] != t.RowCount {
			return nil, 0, fmt.Errorf("%s loaded %d documents; the snapshot recorded %d. The target holds it as loaded; drop it before retrying", t.TableName, counts[t.TableName], t.RowCount)
		}
		docs += counts[t.TableName]
	}
	return created, docs, nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
