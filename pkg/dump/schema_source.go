package dump

// What SchemaSource starts with for a snapshot whose dump holds the whole
// schema: the tool that wrote it, then its version where it has one. A
// reader that judges a snapshot by its schema source (the drill, the web
// console) accepts these and reads anything else as a lossy capture.
const (
	SchemaSourcePgDump       = "pg_dump"
	SchemaSourceMySQLDump    = "mysqldump"
	SchemaSourceMariaDBDump  = "mariadb-dump"
	SchemaSourceMongoDump    = "mongodump"
	SchemaSourceSQLiteVacuum = "sqlite VACUUM INTO"
	SchemaSourceSQLiteBackup = "sqlite online backup"
)

// WholeSchemaSources is every prefix above, and the WordPress plugin's.
var WholeSchemaSources = []string{
	SchemaSourcePgDump, SchemaSourceMySQLDump, SchemaSourceMariaDBDump, SchemaSourceMongoDump,
	SchemaSourceSQLiteVacuum, SchemaSourceSQLiteBackup, WordPressSchemaSource,
}
