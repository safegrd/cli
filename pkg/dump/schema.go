package dump

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
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
			b.WriteString(fmt.Sprintf("CREATE EXTENSION IF NOT EXISTS \"%s\";\n", ext))
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
				b.WriteString(fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS \"%s\";\n", sc))
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
			b.WriteString(fmt.Sprintf("CREATE SEQUENCE IF NOT EXISTS \"%s\".\"%s\";\n", seq.Schema, seq.Name))
		}
		b.WriteString("\n")
	}

	// 3. Tables and Columns
	tables, err := s.extractTables(ctx)
	if err != nil {
		return "", err
	}
	for _, t := range tables {
		b.WriteString(fmt.Sprintf("-- Table: %s.%s\n", t.Schema, t.Name))
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
			typeStr = fmt.Sprintf(`"%s"`, udtName)
		} else if dataType == "character varying" {
			if charLen.Valid && charLen.String != "" {
				typeStr = fmt.Sprintf("VARCHAR(%s)", charLen.String)
			} else {
				typeStr = "VARCHAR"
			}
		}

		colDef := fmt.Sprintf(`    "%s" %s`, colName, typeStr)
		if isNullable == "NO" {
			colDef += " NOT NULL"
		}
		if colDefault.Valid && colDefault.String != "" {
			colDef += " DEFAULT " + colDefault.String
		}

		colDefs = append(colDefs, colDef)
	}

	// Query Primary Keys
	pkQuery := `
		SELECT kcu.column_name
		FROM information_schema.table_constraints tc
		JOIN information_schema.key_column_usage kcu
		  ON tc.constraint_name = kcu.constraint_name
		  AND tc.table_schema = kcu.table_schema
		WHERE tc.constraint_type = 'PRIMARY KEY'
		  AND tc.table_schema = $1 AND tc.table_name = $2
		ORDER BY kcu.ordinal_position;
	`
	pkRows, err := s.db.QueryContext(ctx, pkQuery, schema, table)
	if err == nil {
		var pkCols []string
		for pkRows.Next() {
			var col string
			if err := pkRows.Scan(&col); err == nil {
				pkCols = append(pkCols, fmt.Sprintf(`"%s"`, col))
			}
		}
		pkRows.Close()

		if len(pkCols) > 0 {
			colDefs = append(colDefs, fmt.Sprintf("    PRIMARY KEY (%s)", strings.Join(pkCols, ", ")))
		}
	}

	ddl := fmt.Sprintf("CREATE TABLE IF NOT EXISTS \"%s\".\"%s\" (\n%s\n);",
		schema, table, strings.Join(colDefs, ",\n"))

	return ddl, nil
}

func (s *SchemaExtractor) extractIndexes(ctx context.Context) ([]string, error) {
	query := `
		SELECT indexdef
		FROM pg_indexes
		WHERE schemaname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
		  AND indexname NOT IN (
		      SELECT constraint_name 
		      FROM information_schema.table_constraints 
		      WHERE constraint_type IN ('PRIMARY KEY', 'UNIQUE')
		  )
		ORDER BY schemaname, tablename, indexname;
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
	query := `
		SELECT sequence_schema, sequence_name
		FROM information_schema.sequences
		WHERE sequence_schema NOT IN ('pg_catalog', 'information_schema')
		ORDER BY sequence_schema, sequence_name;
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
