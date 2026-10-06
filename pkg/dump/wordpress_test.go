package dump

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/safegrd/cli/pkg/model"
)

// wpSite is a WordPress archive under construction, in the plugin's layout.
type wpSite struct {
	dump  string
	files map[string]string
	// list overrides files.json; nil lists files as they are.
	list []WordPressFileEntry
}

const wpTestDump = "-- SafeGrd WordPress dump\n" +
	"/*!40101 SET NAMES utf8mb4 */;\n" +
	"DROP TABLE IF EXISTS `wp_posts`;\n" +
	"CREATE TABLE `wp_posts` (\n" +
	"  `ID` bigint unsigned NOT NULL AUTO_INCREMENT,\n" +
	"  `post_title` text NOT NULL,\n" +
	"  PRIMARY KEY (`ID`)\n" +
	") ENGINE=InnoDB;\n\n" +
	"INSERT INTO `wp_posts` VALUES (1,'Hello (world), it\\'s me'),(2,'Photo');\n" +
	"DROP TABLE IF EXISTS `wp_postmeta`;\n" +
	"CREATE TABLE `wp_postmeta` (\n" +
	"  `meta_id` bigint unsigned NOT NULL AUTO_INCREMENT,\n" +
	"  `post_id` bigint unsigned NOT NULL DEFAULT '0',\n" +
	"  `meta_key` varchar(255) DEFAULT NULL,\n" +
	"  `meta_value` longtext,\n" +
	"  PRIMARY KEY (`meta_id`)\n" +
	") ENGINE=InnoDB;\n\n" +
	"INSERT INTO `wp_postmeta` VALUES (1,2,'_wp_attached_file','2026/10/photo.png'),(2,2,'_wp_attachment_metadata','a:1:{s:4:\\\"file\\\";s:17:\\\"_wp_attached_file\\\";}'),(3,1,'_edit_lock',NULL);\n" +
	"INSERT INTO `wp_postmeta` VALUES (4,3,'_wp_attached_file','2026/10/it\\'s.pdf');\n" +
	"-- Dump completed on 2026-10-06 12:00:00\n"

func newWPSite() *wpSite {
	return &wpSite{dump: wpTestDump, files: map[string]string{
		"wp-config.php":                        "<?php define('DB_NAME', 'wp');",
		"wp-content/uploads/2026/10/photo.png": "\x89PNG not really",
		"wp-content/uploads/2026/10/it's.pdf":  "%PDF-1.7",
		"wp-content/themes/theme/style.css":    "body{}",
	}}
}

func (s *wpSite) archive(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	put := func(name string, body []byte) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	put("mysql/dump.sql", []byte(s.dump))
	list := s.list
	var total int64
	for p, body := range s.files {
		put("files/"+p, []byte(body))
		if s.list == nil {
			sum := sha256.Sum256([]byte(body))
			list = append(list, WordPressFileEntry{Path: p, Size: int64(len(body)), Sha256: hex.EncodeToString(sum[:])})
		}
	}
	for _, f := range list {
		total += f.Size
	}
	data, _ := json.Marshal(list)
	put("files.json", data)
	meta := model.SnapshotMetadata{
		SurfaceType: model.SurfaceTypeWordPress, DatabaseName: "wp", SchemaSource: WordPressSchemaSource + " 0.1.0",
		TableStats: []model.TableStat{{Schema: "wp", TableName: "wp_postmeta", RowCount: 4}, {Schema: "wp", TableName: "wp_posts", RowCount: 2}},
		WordPress:  &model.WordPressStats{TablePrefix: "wp_", UploadsPath: "wp-content/uploads", TotalFiles: int64(len(list)), FileBytes: total},
	}
	meta.CalculateTotals()
	data, _ = json.Marshal(meta)
	put("manifest.json", data)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func inspectWP(t *testing.T, s *wpSite) (*DryRestoreResult, map[string]model.AssertionResult) {
	t.Helper()
	res, err := InspectWordPressArchive(context.Background(), bytes.NewReader(s.archive(t)))
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]model.AssertionResult{}
	for _, a := range res.Assertions {
		byName[a.Name] = a
	}
	return res, byName
}

func TestAWordPressArchivePassesWhenEveryHalfAgrees(t *testing.T) {
	res, got := inspectWP(t, newWPSite())
	if !res.Passed {
		for _, a := range res.Assertions {
			if !a.Passed {
				t.Errorf("%s: expected %s, got %s", a.Name, a.Expected, a.Actual)
			}
		}
		t.Fatalf("the drill failed a sound archive: %s", res.ErrorMessage)
	}
	if res.TotalRows != 6 || res.TotalTables != 2 {
		t.Errorf("counted %d rows in %d tables, want 6 in 2", res.TotalRows, res.TotalTables)
	}
	if a := got["Attachments Present"]; !strings.HasPrefix(a.Actual, "2 of 2") {
		t.Errorf("the attachment check read %q, want both attachments the dump names, the escaped one included", a.Actual)
	}
}

// The list of attachments comes from the database half, so an archive whose
// file list agrees with its files still fails when the database names an
// upload the archive does not hold.
func TestAWordPressArchiveFailsWhenAnAttachmentTheDatabaseNamesIsMissing(t *testing.T) {
	s := newWPSite()
	delete(s.files, "wp-content/uploads/2026/10/photo.png")
	res, got := inspectWP(t, s)
	if res.Passed {
		t.Fatal("the drill passed a site whose database names an upload the archive lacks")
	}
	a := got["Attachments Present"]
	if a.Passed || !strings.Contains(a.Actual, "wp-content/uploads/2026/10/photo.png") {
		t.Errorf("the attachment check did not name the missing file: %+v", a)
	}
	if !got["Files Present"].Passed || !got["File Contents Match"].Passed {
		t.Error("the file list agrees with the files here; only the attachment check should fail")
	}
}

func TestAWordPressArchiveFailsWhenAFileDiffersFromItsList(t *testing.T) {
	s := newWPSite()
	for p, body := range s.files {
		b := sha256.Sum256([]byte(body))
		s.list = append(s.list, WordPressFileEntry{Path: p, Size: int64(len(body)), Sha256: hex.EncodeToString(b[:])})
	}
	s.files["wp-content/themes/theme/style.css"] = "body{color:red}"
	res, got := inspectWP(t, s)
	if res.Passed || got["File Contents Match"].Passed {
		t.Fatalf("the drill passed a file whose bytes differ from its listed digest: %+v", got["File Contents Match"])
	}
}

func TestAWordPressArchiveFailsWhenTheDumpStopsPartWay(t *testing.T) {
	s := newWPSite()
	s.dump = strings.TrimSuffix(s.dump, "-- Dump completed on 2026-10-06 12:00:00\n")
	res, got := inspectWP(t, s)
	if res.Passed || got["Dump Complete"].Passed {
		t.Fatal("the drill passed a dump with no completion line")
	}
}

func TestAWordPressArchiveRefusesAPathOutsideTheSite(t *testing.T) {
	s := newWPSite()
	s.files["../../etc/passwd"] = "root"
	res, _ := inspectWP(t, s)
	if res.Passed || !strings.Contains(res.ErrorMessage, "outside the site") {
		t.Fatalf("the drill read a file outside the site: %+v", res.ErrorMessage)
	}
}
