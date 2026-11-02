package dump

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// SchemaExtractor generates DDL SQL statements directly from PostgreSQL catalog tables.
type SchemaExtractor struct {
	db *sql.DB
}

// NewSchemaExtractor creates a new schema extractor.
func NewSchemaExtractor(db *sql.DB) *SchemaExtractor {
	return &SchemaExtractor{db: db}
}

// ExtractDDL returns complete SQL DDL commands to recreate extensions, schemas, tables, and indexes.
func (s *SchemaExtractor) ExtractDDL(ctx context.Context) (string, error) {
	var b strings.Builder

	b.WriteString("-- SafeGrd Pure Go Native DDL Schema Dump\n\n")

	// 1. Extensions
	exts, err := s.extractExtensions(ctx)
	if err != nil {
		return "", err
	}
	if len(exts) > 0 {
		b.WriteString("-- Extensions\n")
		for _, ext := range exts {
			b.WriteString(fmt.Sprintf("CREATE EXTENSION IF NOT EXISTS %s;\n", quoteIdent(ext)))
		}
		b.WriteString("\n")
	}

	// 2. Custom Schemas
	schemas, err := s.extractSchemas(ctx)
	if err != nil {
		return "", err
	}
	if len(schemas) > 0 {
		b.WriteString("-- Custom Schemas\n")
		for _, sc := range schemas {
			if sc != "public" {
				b.WriteString(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s;\n", quoteIdent(sc)))
			}
		}
		b.WriteString("\n")
	}

	// 2.5 Sequences (must precede tables for SERIAL/nextval defaults)
	seqs, err := s.extractSequences(ctx)
	if err != nil {
		return "", err
	}
	if len(seqs) > 0 {
		b.WriteString("-- Sequences\n")
		for _, seq := range seqs {
			b.WriteString(fmt.Sprintf("CREATE SEQUENCE IF NOT EXISTS %s;\n", quoteIdent(seq.Schema, seq.Name)))
		}
		b.WriteString("\n")
	}

	// 3. Tables and Columns
	tables, err := s.extractTables(ctx)
	if err != nil {
		return "", err
	}
	for _, t := range tables {
		b.WriteString(fmt.Sprintf("-- Table: %s.%s\n", oneLine(t.Schema), oneLine(t.Name)))
		tableDDL, err := s.generateTableDDL(ctx, t.Schema, t.Name)
		if err != nil {
			return "", err
		}
		b.WriteString(tableDDL)
		b.WriteString("\n\n")
	}

	// 4. Indexes
	indexes, err := s.extractIndexes(ctx)
	if err != nil {
		return "", err
	}
	if len(indexes) > 0 {
		b.WriteString("-- Indexes\n")
		for _, idx := range indexes {
			b.WriteString(idx + ";\n")
		}
		b.WriteString("\n")
	}

	return b.String(), nil
}

// quoteIdent quotes a catalog name for the DDL, doubling any quote inside
// it: a table named a"b otherwise ends the identifier early and the schema
// fails to load at restore.
func quoteIdent(parts ...string) string {
	return pgx.Identifier(parts).Sanitize()
}

// oneLine keeps a catalog name inside its comment line: a name may hold a
// newline, and what followed it would be read as SQL.
func oneLine(name string) string {
	return strings.NewReplacer("\n", " ", "\r", " ").Replace(name)
}

type tableRef struct {
	Schema string
	Name   string
}

func (s *SchemaExtractor) extractExtensions(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT extname FROM pg_extension WHERE extname != 'plpgsql' ORDER BY extname;")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		list = append(list, name)
	}
	return list, rows.Err()
}

func (s *SchemaExtractor) extractSchemas(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT schema_name 
		FROM information_schema.schemata 
		WHERE schema_name NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
		ORDER BY schema_name;
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		list = append(list, name)
	}
	return list, rows.Err()
}

func (s *SchemaExtractor) extractTables(ctx context.Context) ([]tableRef, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT table_schema, table_name
		FROM information_schema.tables
		WHERE table_type = 'BASE TABLE'
		  AND table_schema NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
		ORDER BY table_schema, table_name;
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []tableRef
	for rows.Next() {
		var ref tableRef
		if err := rows.Scan(&ref.Schema, &ref.Name); err != nil {
			return nil, err
		}
		list = append(list, ref)
	}
	return list, rows.Err()
}

func (s *SchemaExtractor) generateTableDDL(ctx context.Context, schema, table string) (string, error) {
	query := `
		SELECT 
			column_name, 
			data_type, 
			udt_name,
			is_nullable, 
			column_default,
			character_maximum_length
		FROM information_schema.columns
		WHERE table_schema = $1 AND table_name = $2
		ORDER BY ordinal_position;
	`
	rows, err := s.db.QueryContext(ctx, query, schema, table)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	var colDefs []string
	for rows.Next() {
		var colName, dataType, udtName, isNullable string
		var colDefault, charLen sql.NullString

		if err := rows.Scan(&colName, &dataType, &udtName, &isNullable, &colDefault, &charLen); err != nil {
			return "", err
		}

		typeStr := dataType
		if dataType == "USER-DEFINED" {
			typeStr = quoteIdent(udtName)
		} else if dataType == "character varying" {
			if charLen.Valid && charLen.String != "" {
				typeStr = fmt.Sprintf("VARCHAR(%s)", charLen.String)
			} else {
				typeStr = "VARCHAR"
			}
		}

		colDef := fmt.Sprintf(`    %s %s`, quoteIdent(colName), typeStr)
		if isNullable == "NO" {
			colDef += " NOT NULL"
		}
		if colDefault.Valid && colDefault.String != "" {
			colDef += " DEFAULT " + colDefault.String
		}

		colDefs = append(colDefs, colDef)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}

	// The primary key comes from pg_constraint, which every role reads.
	// information_schema.table_constraints lists only the constraints of
	// tables the role owns or holds a privilege on other than SELECT, so a
	// read-only backup role saw no primary key and the restored table had none.
	pkQuery := `
		SELECT a.attname
		FROM pg_constraint con
		JOIN pg_class c ON c.oid = con.conrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN LATERAL unnest(con.conkey) WITH ORDINALITY AS k(attnum, ord) ON true
		JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = k.attnum
		WHERE con.contype = 'p' AND n.nspname = $1 AND c.relname = $2
		ORDER BY k.ord;
	`
	pkRows, err := s.db.QueryContext(ctx, pkQuery, schema, table)
	if err != nil {
		return "", fmt.Errorf("primary key of %s: %w", quoteIdent(schema, table), err)
	}
	var pkCols []string
	for pkRows.Next() {
		var col string
		if err := pkRows.Scan(&col); err != nil {
			pkRows.Close()
			return "", err
		}
		pkCols = append(pkCols, quoteIdent(col))
	}
	pkRows.Close()
	if err := pkRows.Err(); err != nil {
		return "", err
	}
	if len(pkCols) > 0 {
		colDefs = append(colDefs, fmt.Sprintf("    PRIMARY KEY (%s)", strings.Join(pkCols, ", ")))
	}

	ddl := fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (\n%s\n);",
		quoteIdent(schema, table), strings.Join(colDefs, ",\n"))

	return ddl, nil
}

func (s *SchemaExtractor) extractIndexes(ctx context.Context) ([]string, error) {
	// Every index but the one behind a primary key, which the table's DDL
	// creates. A unique constraint's index is kept as a unique index: this
	// schema carries no constraints but the primary key, and leaving the
	// index out lost the uniqueness. The constraints are read from
	// pg_constraint, which a read-only role sees whole.
	query := `
		SELECT pg_get_indexdef(i.indexrelid)
		FROM pg_index i
		JOIN pg_class ic ON ic.oid = i.indexrelid
		JOIN pg_class tc ON tc.oid = i.indrelid
		JOIN pg_namespace n ON n.oid = tc.relnamespace
		WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
		  AND tc.relkind IN ('r', 'p', 'm')
		  AND NOT EXISTS (
		      SELECT 1 FROM pg_constraint con
		      WHERE con.conindid = i.indexrelid AND con.contype = 'p'
		  )
		ORDER BY n.nspname, tc.relname, ic.relname;
	`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var indexes []string
	for rows.Next() {
		var def string
		if err := rows.Scan(&def); err != nil {
			return nil, err
		}
		indexes = append(indexes, def)
	}
	return indexes, rows.Err()
}

type seqRef struct {
	Schema string
	Name   string
}

func (s *SchemaExtractor) extractSequences(ctx context.Context) ([]seqRef, error) {
	// From pg_class: information_schema.sequences lists only the sequences
	// the role holds a privilege on, and a read-only role granted SELECT on
	// tables alone saw none, so every serial column's default named a
	// sequence the schema never created.
	query := `
		SELECT n.nspname, c.relname
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind = 'S'
		  AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
		ORDER BY n.nspname, c.relname;
	`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []seqRef
	for rows.Next() {
		var ref seqRef
		if err := rows.Scan(&ref.Schema, &ref.Name); err != nil {
			return nil, err
		}
		list = append(list, ref)
	}
	return list, rows.Err()
}
