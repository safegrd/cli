package dump

import (
	"context"
	"io"

	"github.com/safegrd/cli/pkg/model"
)

// EngineType names a Postgres backup engine. There is one: the schema from
// pg_dump and the rows over binary COPY (native.go). "toolchain" used to write
// a pg_dump custom-format archive that no Fire Drill could read, so a backup
// taken with it could never be proven; it is accepted and
// means the same thing, so existing scripts keep working.
type EngineType string

const (
	EngineTypeNative    EngineType = "native"
	EngineTypeToolchain EngineType = "toolchain"
	EngineTypeAuto      EngineType = "auto"
)

// Dumper handles database extraction.
type Dumper interface {
	Dump(ctx context.Context, databaseName string, dst io.Writer) (*model.SnapshotMetadata, error)
}

// Restorer handles database restoration.
type Restorer interface {
	Restore(ctx context.Context, src io.Reader) (*model.SnapshotMetadata, error)
}

// NewDumper returns the dumper for a database URL: MySQL or MariaDB for
// mysql:// and mariadb://, Postgres for everything else.
func NewDumper(_ EngineType, databaseURL string) Dumper {
	if IsMongoURL(databaseURL) {
		return NewMongoDumper(databaseURL)
	}
	if IsMySQLURL(databaseURL) {
		return NewMySQLDumper(databaseURL)
	}
	return NewNativeDumper(databaseURL)
}

// NewRestorer returns the restorer for a target URL.
func NewRestorer(_ EngineType, targetURL string) Restorer {
	if IsMongoURL(targetURL) {
		return NewMongoRestorer(targetURL)
	}
	if IsMySQLURL(targetURL) {
		return NewMySQLRestorer(targetURL)
	}
	return NewNativeRestorer(targetURL)
}

// SurfaceTypeOfURL is the database surface a connection URL selects.
func SurfaceTypeOfURL(u string) model.SurfaceType {
	switch {
	case IsMongoURL(u):
		return model.SurfaceTypeMongoDB
	case IsMySQLURL(u):
		return model.SurfaceTypeMySQL
	}
	return model.SurfaceTypePostgres
}
