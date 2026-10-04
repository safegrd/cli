package dump

import (
	"fmt"
	"strings"

	"github.com/safegrd/cli/pkg/model"
)

// A recovery document sits beside every snapshot: plain text that says what
// the snapshot is, where it is, what a restore needs and the commands that
// restore it, for a reader who has the bucket and the key and nothing else.
// Its purpose is to be readable after the control plane is gone, so it is
// written unsealed unless the surface asks otherwise, and its renderer takes
// no credential type, so no secret can reach it.

// Location is where a snapshot is, with nothing that opens it.
type Location struct {
	// Kind is "s3", "local" or "hosted".
	Kind     string
	Bucket   string
	Endpoint string
	Region   string
	// Prefix is the key prefix the snapshot's objects sit under, the node
	// segment included; for a directory, the directory.
	Prefix string
}

// RenderRecoveryDoc writes the recovery document for meta at loc: 80
// columns, no secrets.
func RenderRecoveryDoc(meta *model.SnapshotMetadata, loc Location) []byte {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	surface := meta.SurfaceType
	if surface == "" {
		surface = model.SurfaceTypePostgres
	}
	what := surfaceWords(surface)
	if meta.DatabaseName != "" && surface.IsDatabase() {
		what = surfaceWords(surface) + " database " + meta.DatabaseName
	}
	w("SafeGrd recovery document for snapshot %s", meta.SnapshotID)
	w("%s", strings.Repeat("=", len("SafeGrd recovery document for snapshot "+meta.SnapshotID)))
	w("")
	w("A backup of the %s, taken %s.", what, meta.CreatedAt.UTC().Format("2006-01-02 15:04 UTC"))
	w("This file says how to restore it with the bucket and the key alone. It holds")
	w("no secret: no credential, no key, no connection string.")
	w("")
	w("Where it is")
	w("-----------")
	switch loc.Kind {
	case "hosted":
		w("SafeGrd hosted storage, under compliance-mode Object Lock. Download it from the")
		w("console (the snapshot's row, Download) or with the CLI on an enrolled host; the")
		w("console serves it while your account exists, and the Age key opens it anywhere.")
	case "local":
		w("A directory on the host that took the backup: %s", loc.Prefix)
	default:
		if loc.Endpoint != "" {
			w("Bucket %s at %s (region %s), under %s/", loc.Bucket, loc.Endpoint, orDash(loc.Region), loc.Prefix)
		} else {
			w("Bucket %s (region %s), under %s/", loc.Bucket, orDash(loc.Region), loc.Prefix)
		}
	}
	if meta.IsRepo() {
		w("Format: a run of an incremental repository (%s), epoch %s. The CLI reads it", meta.Format, orDash(meta.EpochID))
		w("back as one archive; its content root is %s.", orDash(meta.Sha256Checksum))
	} else {
		w("Archive: %s.safegrd, %s encrypted (zstd, then age X25519).", meta.SnapshotID, byteCount(meta.EncryptedSizeBytes))
		w("Sidecar: %s.meta.json, the manifest with every table's row count.", meta.SnapshotID)
		if meta.Sha256Checksum != "" {
			w("SHA-256 of the plaintext: %s", meta.Sha256Checksum)
		}
	}
	switch {
	case meta.WORMMode == "NONE":
		w("Not locked: this storage applies no Object Lock.")
	case !meta.WORMRetentionUntil.IsZero():
		w("Locked until %s (%s): it cannot be deleted before then.", meta.WORMRetentionUntil.UTC().Format("2006-01-02"), orDash(meta.WORMMode))
	}
	w("")
	w("What a restore needs")
	w("--------------------")
	w("- The Age private key this snapshot was sealed to. If SafeGrd keeps your key, an")
	w("  enrolled host fetches it; if you keep it, it is the key file from `safegrd init`.")
	w("- The safegrd CLI: https://github.com/safegrd/cli (Go: go build ./cmd/safegrd).")
	switch surface {
	case model.SurfaceTypePostgres:
		w("- An empty PostgreSQL database on %s.", serverNeed("PostgreSQL", meta.PostgresVersion))
		if len(meta.Extensions) > 0 {
			w("- These extensions available on that server: %s.", strings.Join(meta.Extensions, ", "))
		}
		if len(meta.RolesNamed) > 0 {
			w("- Roles the schema names: %s. The restore creates the ones the", strings.Join(meta.RolesNamed, ", "))
			if strings.Contains(meta.RolesSource, "no passwords") {
				w("  server lacks, without passwords; set them afterwards.")
			} else if meta.RolesSource != "" {
				w("  server lacks, with their passwords.")
			} else {
				w("  server lacks only if roles.sql is in the snapshot; this one has none, so")
				w("  create them first.")
			}
		}
	case model.SurfaceTypeMySQL:
		w("- An empty MySQL or MariaDB database on %s, and the mysql client.", serverNeed("the server version", meta.ServerVersion))
	case model.SurfaceTypeMongoDB:
		w("- An empty MongoDB database and the MongoDB Database Tools (mongorestore).")
	case model.SurfaceTypeSQLite:
		w("- A path for the new database file. Nothing else.")
	case model.SurfaceTypeFiles:
		w("- A directory to restore into. Run as root to restore ownership.")
	case model.SurfaceTypeEmail:
		w("- A directory to restore into; messages come back as .eml files.")
	}
	w("")
	w("Restore")
	w("-------")
	w("With a config that names this storage (safegrd init, or the host's config):")
	switch {
	case surface == model.SurfaceTypeFiles || surface == model.SurfaceTypeEmail:
		w("  safegrd restore --snapshot %s --target-dir ./recovered", meta.SnapshotID)
	case surface == model.SurfaceTypeSQLite:
		w("  safegrd restore --snapshot %s --target sqlite:///path/to/new.db", meta.SnapshotID)
	case surface == model.SurfaceTypeMongoDB:
		w("  # TARGET_URL is mongodb://.../empty_db")
		w("  safegrd restore --snapshot %s --target env:TARGET_URL", meta.SnapshotID)
	case surface == model.SurfaceTypeMySQL:
		w("  # TARGET_URL is mysql://.../empty_db")
		w("  safegrd restore --snapshot %s --target env:TARGET_URL", meta.SnapshotID)
	default:
		w("  createdb recovered")
		w("  # TARGET_URL is postgres://.../recovered")
		w("  safegrd restore --snapshot %s --target env:TARGET_URL", meta.SnapshotID)
		w("Without SafeGrd's restore code, as files psql loads:")
		w("  safegrd restore --snapshot %s --to-sql ./out", meta.SnapshotID)
		w("  cd out && psql \"$TARGET_URL\" -f load.sql")
	}
	if loc.Kind == "s3" {
		w("A config for this storage, with the bucket's read credentials in the environment:")
		w("  storage:")
		w("    type: s3")
		w("    bucket: %s", loc.Bucket)
		if loc.Endpoint != "" {
			w("    endpoint: %s", loc.Endpoint)
			w("    force_path_style: true")
		}
		if loc.Region != "" {
			w("    region: %s", loc.Region)
		}
		w("    prefix: %s", strings.TrimSuffix(strings.TrimSuffix(loc.Prefix, "/"+meta.NodeID), "/"))
		if meta.NodeID != "" {
			w("  node_id: %s", meta.NodeID)
		}
	}
	w("The restore checks the digest above before it reports success, and refuses a target")
	w("that already holds data.")
	w("")
	w("What this snapshot does not contain")
	w("-----------------------------------")
	var gaps []string
	for _, t := range meta.TableStats {
		if t.RowSecurity {
			gaps = append(gaps, fmt.Sprintf("- %s.%s: only the rows row-level security showed the backup role (%d copied).", t.Schema, t.TableName, t.RowCount))
		}
	}
	if surface == model.SurfaceTypePostgres && strings.Contains(meta.RolesSource, "no passwords") {
		gaps = append(gaps, "- Role passwords: the roles come back without them.")
	}
	if surface == model.SurfaceTypePostgres {
		gaps = append(gaps, "- Anything outside this database: other databases, server settings, replication.")
	}
	if surface == model.SurfaceTypeFiles {
		gaps = append(gaps, "- Hard links (each comes back as its own copy), extended attributes and ACLs, setuid bits.")
	}
	if surface == model.SurfaceTypeMongoDB {
		gaps = append(gaps, "- Users and roles, which are server-wide; and the oplog, so collections are each consistent, not together.")
	}
	if len(gaps) == 0 {
		gaps = append(gaps, "- Nothing known. The manifest lists every table or file and its count.")
	}
	for _, g := range gaps {
		w("%s", g)
	}
	return []byte(b.String())
}

// surfaceWords is the surface as a reader names it.
func surfaceWords(s model.SurfaceType) string {
	switch s {
	case model.SurfaceTypePostgres:
		return "PostgreSQL"
	case model.SurfaceTypeMySQL:
		return "MySQL or MariaDB"
	case model.SurfaceTypeMongoDB:
		return "MongoDB"
	case model.SurfaceTypeSQLite:
		return "SQLite"
	case model.SurfaceTypeFiles:
		return "directory tree"
	case model.SurfaceTypeEmail:
		return "mailbox"
	}
	return string(s)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// serverNeed is "PostgreSQL 16 or newer" from a version string, or the
// product alone when the version is unknown.
func serverNeed(product, version string) string {
	v := strings.TrimSpace(version)
	if product == "PostgreSQL" && strings.HasPrefix(v, "PostgreSQL ") {
		v = strings.TrimPrefix(v, "PostgreSQL ")
		if j := strings.Index(v, " "); j > 0 {
			v = v[:j]
		}
	}
	if v == "" {
		return product
	}
	if product == "PostgreSQL" {
		if major, _, ok := strings.Cut(v, "."); ok {
			return "PostgreSQL " + major + " or newer"
		}
		return "PostgreSQL " + v + " or newer"
	}
	return product + " " + v + " or newer"
}

func byteCount(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d bytes", n)
}
