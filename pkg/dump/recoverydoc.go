package dump

import (
	"fmt"
	"strings"

	"github.com/safegrd/cli/pkg/model"
)

// A recovery document sits beside every snapshot: plain text that says what
// the snapshot is, where it is, what a restore needs and the commands that
// restore it, for a reader who has the bucket and the key and nothing else.
// It is written unsealed unless the surface asks otherwise, so it can be read
// without SafeGrd, and its renderer takes no credential type, so no secret
// can reach it. Lines stay under 100 columns, except a bucket or folder name
// that is longer by itself.

// Location is where a snapshot is, with nothing that opens it.
type Location struct {
	// Kind is "s3", "local" or "hosted".
	Kind     string
	Bucket   string
	Endpoint string
	Region   string
	// Prefix is the folder the snapshot's objects sit in: for an archive,
	// the storage prefix and the node segment; for an incremental run, its
	// epoch's folder. For a directory, the directory.
	Prefix string
	// ConfigPrefix is the storage prefix as a config names it, without the
	// node segment the CLI adds.
	ConfigPrefix string
}

// RenderRecoveryDoc writes the recovery document for meta at loc.
func RenderRecoveryDoc(meta *model.SnapshotMetadata, loc Location) []byte {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	heading := func(h string) { w(""); w("%s", h); w("%s", strings.Repeat("-", len(h))) }
	surface := meta.SurfaceType
	if surface == "" {
		surface = model.SurfaceTypePostgres
	}
	what := surfaceWords(surface)
	if meta.DatabaseName != "" && surface.IsDatabase() {
		what += " database " + meta.DatabaseName
	}
	repo := meta.IsRepo()
	title := "SafeGrd recovery document: " + meta.SnapshotID
	w("%s", title)
	w("%s", strings.Repeat("=", len(title)))
	w("")
	w("Backup of the %s, taken %s.", what, meta.CreatedAt.UTC().Format("2006-01-02 15:04 UTC"))
	w("This file lists where the backup is, what a restore needs and the commands")
	w("that restore it. It contains no credentials, keys or connection strings.")

	heading("Location")
	switch loc.Kind {
	case "hosted":
		w("SafeGrd hosted storage.")
		if repo {
			w("Restore it with the safegrd CLI on one of your enrolled hosts. The console")
			w("offers this file and the manifest for download from the snapshot's details.")
		} else {
			w("Download the backup and its manifest from the snapshot's details in the")
			w("console, or restore it with the safegrd CLI on one of your enrolled hosts.")
		}
	case "local":
		w("Directory: %s", loc.Prefix)
		w("on the host that took the backup.")
	default:
		w("Bucket:   %s", loc.Bucket)
		if loc.Endpoint != "" {
			w("Endpoint: %s", loc.Endpoint)
		}
		if loc.Region != "" {
			w("Region:   %s", loc.Region)
		}
		w("Folder:   %s/", strings.TrimSuffix(loc.Prefix, "/"))
	}
	if repo {
		w("Backup:   incremental. It is stored as chunks in its folder, shared with")
		w("          the other backups taken this month, so there is no single file.")
		w("Manifest: snapshots/%s.meta.json in that folder.", meta.SnapshotID)
		if meta.Sha256Checksum != "" {
			w("Checksum: %s (content root, over every file's SHA-256)", meta.Sha256Checksum)
		}
	} else {
		w("Backup:   %s.safegrd (%s, zstd, encrypted with age)", meta.SnapshotID, byteCount(meta.EncryptedSizeBytes))
		w("Manifest: %s.meta.json (every table or file, with its count)", meta.SnapshotID)
		if meta.Sha256Checksum != "" {
			w("Checksum: %s (SHA-256 of the unencrypted backup)", meta.Sha256Checksum)
		}
	}
	switch {
	case meta.WORMMode == "NONE":
		w("Not locked: this storage has no Object Lock.")
	case !meta.WORMRetentionUntil.IsZero():
		w("Locked until %s (Object Lock, %s mode). It cannot be deleted before then.",
			meta.WORMRetentionUntil.UTC().Format("2006-01-02"), strings.ToLower(orDash(meta.WORMMode)))
	}

	heading("What a restore needs")
	w("- The age private key this backup was encrypted to.")
	w("  SafeGrd-managed key: SafeGrd keeps your key sealed and releases it only to")
	w("  your enrolled hosts, so you can restore even after losing a host. Run the")
	w("  restore on an enrolled host.")
	w("  Customer-managed key: the key file `safegrd init` wrote (key_path in")
	w("  ~/.safegrd/config.yaml), or the key in SAFEGRD_PRIVATE_KEY.")
	w("- The safegrd CLI:")
	w("    curl -fsSL https://safegrd.dev/install.sh | sh")
	w("  or a binary from https://github.com/safegrd/cli/releases")
	switch surface {
	case model.SurfaceTypePostgres:
		w("- An empty database on %s.", serverNeed("PostgreSQL", meta.PostgresVersion))
		if len(meta.Extensions) > 0 {
			w("- These extensions installed on that server: %s.", strings.Join(meta.Extensions, ", "))
		}
		if len(meta.RolesNamed) > 0 {
			w("- Roles the schema uses: %s.", strings.Join(meta.RolesNamed, ", "))
			switch {
			case strings.Contains(meta.RolesSource, "no passwords"):
				w("  The restore creates the missing ones without passwords. Set their")
				w("  passwords afterwards.")
			case meta.RolesSource != "":
				w("  The restore creates the missing ones, with their passwords.")
			default:
				w("  This backup has no roles.sql. Create these roles before the restore.")
			}
		}
	case model.SurfaceTypeMySQL:
		w("- An empty database on %s, and the mysql client.", serverNeed("MySQL or MariaDB", meta.ServerVersion))
	case model.SurfaceTypeMongoDB:
		w("- An empty MongoDB database, and mongorestore (MongoDB Database Tools).")
	case model.SurfaceTypeSQLite:
		w("- A path for the new database file.")
	case model.SurfaceTypeFiles:
		w("- An empty directory to restore into. Run as root to restore file owners.")
	case model.SurfaceTypeEmail:
		w("- An empty directory to restore into. Messages come back as .eml files.")
	}

	heading("Restore")
	switch loc.Kind {
	case "s3":
		w("On the host that took the backup, its config already names this storage.")
		w("Elsewhere, put this in ~/.safegrd/config.yaml, with the bucket's read")
		w("credentials in AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY:")
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
		if loc.ConfigPrefix != "" {
			w("    prefix: %s", loc.ConfigPrefix)
		}
		if meta.NodeID != "" {
			w("    node_id: %s", meta.NodeID)
		}
		w("Then run:")
	case "local":
		w("On the host that took the backup, run:")
	default:
		w("On an enrolled host, run:")
	}
	switch surface {
	case model.SurfaceTypeFiles, model.SurfaceTypeEmail:
		w("  safegrd restore --snapshot %s --target-dir ./recovered", meta.SnapshotID)
	case model.SurfaceTypeSQLite:
		w("  safegrd restore --snapshot %s --target sqlite:///path/to/new.db", meta.SnapshotID)
	case model.SurfaceTypeMongoDB:
		w("  export TARGET_URL=mongodb://.../empty_db")
		w("  safegrd restore --snapshot %s --target env:TARGET_URL", meta.SnapshotID)
	case model.SurfaceTypeMySQL:
		w("  export TARGET_URL=mysql://.../empty_db")
		w("  safegrd restore --snapshot %s --target env:TARGET_URL", meta.SnapshotID)
	default:
		w("  createdb recovered")
		w("  export TARGET_URL=postgres://.../recovered")
		w("  safegrd restore --snapshot %s --target env:TARGET_URL", meta.SnapshotID)
		w("To get plain SQL files instead and load them with psql:")
		w("  safegrd restore --snapshot %s --to-sql ./out", meta.SnapshotID)
		w("  cd out && psql \"$TARGET_URL\" -f load.sql")
	}
	w("The restore checks the checksum above before it reports success. It refuses")
	w("a target that already holds data.")

	heading("Not in this backup")
	var gaps []string
	for _, t := range meta.TableStats {
		if t.RowSecurity {
			gaps = append(gaps, fmt.Sprintf("- %s.%s: only the %d rows row-level security showed the backup role.", t.Schema, t.TableName, t.RowCount))
		}
	}
	switch surface {
	case model.SurfaceTypePostgres:
		if strings.Contains(meta.RolesSource, "no passwords") {
			gaps = append(gaps, "- Role passwords.")
		}
		gaps = append(gaps, "- Other databases on the server, server settings and replication setup.")
	case model.SurfaceTypeFiles:
		gaps = append(gaps, "- Hard links (each comes back as a separate copy), extended attributes,",
			"  ACLs and setuid bits.")
	case model.SurfaceTypeMongoDB:
		gaps = append(gaps, "- Users and roles, which are server-wide.",
			"- The oplog: each collection is consistent by itself, not with the others.")
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
