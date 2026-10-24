package dump

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// MongoOplogReplay applies the oplog entries in oplogFile (BSON documents
// one after another, as oplog.bson holds them) to the target server with
// mongorestore --oplogReplay, stopping before limitSecs:limitOrd. The
// entries must already name the target database: mongorestore refuses to
// rename during a replay.
func MongoOplogReplay(ctx context.Context, targetURL, oplogFile string, limitSecs, limitOrd uint32) error {
	tool, err := findMongoTool(ctx, "mongorestore")
	if err != nil {
		return err
	}
	cfgPath, cleanup, err := mongoToolConfig(withoutDatabase(targetURL))
	if err != nil {
		return err
	}
	defer cleanup()
	empty, err := privateWorkDir(".safegrd-oplog-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(empty)
	args := []string{"--config=" + cfgPath, "--oplogReplay", "--oplogFile=" + oplogFile,
		fmt.Sprintf("--oplogLimit=%d:%d", limitSecs, limitOrd), "--stopOnError", empty}
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, tool.Path, args...)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := toolMessage(stderr.String())
		if len(msg) > 800 {
			msg = msg[:800] + "..."
		}
		return fmt.Errorf("%s --oplogReplay failed: %v: %s", tool, err, strings.TrimSpace(msg))
	}
	return nil
}

// MongoDatabaseName is the database a mongodb:// URL names.
func MongoDatabaseName(raw string) (string, error) { return mongoDatabase(raw) }
