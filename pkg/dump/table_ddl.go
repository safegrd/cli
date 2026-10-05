package dump

import (
	"regexp"
	"strings"
)

// TableDDL is what a schema-only pg_dump holds for one table: the table and
// the sequences it owns, then its constraints, indexes, policies and triggers.
// A restore of one table into a database that no longer has it runs Create,
// loads the rows, then runs Setvals.
type TableDDL struct {
	Create  string // pre-data and post-data objects of the table, in dump order
	Setvals string // sequences.sql lines for the sequences the table owns
	Objects int    // how many dump objects Create holds
}

// TableDefinition picks the objects of schema.table, and of the sequences it
// owns (owned holds them as quote_ident(schema).quote_ident(name)), out of a
// run's pre-data, post-data and sequences sections. ok is false when the
// dump holds no TABLE entry for it.
func TableDefinition(preData, postData, sequences, schema, table string, owned []string) (ddl TableDDL, ok bool) {
	quals := qualifiedForms(schema, table)
	ownedSeq := map[string]bool{}
	for _, o := range owned {
		s, n := splitQualified(o)
		ownedSeq[s+"\x00"+n] = true
	}
	var b strings.Builder
	for _, section := range []string{preData, postData} {
		matches := tocHeaderRe.FindAllStringSubmatchIndex(section, -1)
		for i, m := range matches {
			end := len(section)
			if i+1 < len(matches) {
				end = matches[i+1][0]
			}
			name, typ, objSchema := section[m[2]:m[3]], section[m[4]:m[5]], section[m[6]:m[7]]
			body := section[m[1]:end]
			if !tableObject(name, typ, objSchema, body, schema, table, quals, ownedSeq) {
				continue
			}
			if typ == "TABLE" {
				ok = true
			}
			b.WriteString(section[m[0]:end])
			ddl.Objects++
		}
	}
	if !ok {
		return TableDDL{}, false
	}
	ddl.Create = b.String()
	// sequences.sql names a sequence fully quoted ('"public"."orders_id_seq"');
	// pg_dump's own setval does not quote what needs none.
	var forms []string
	for _, o := range owned {
		sch, n := splitQualified(o)
		q := `"` + strings.ReplaceAll(sch, `"`, `""`) + `"."` + strings.ReplaceAll(n, `"`, `""`) + `"`
		forms = append(forms, "setval('"+o+"'", "setval('"+strings.ReplaceAll(q, "'", "''")+"'")
	}
	var s strings.Builder
	for _, line := range strings.SplitAfter(sequences, "\n") {
		for _, f := range forms {
			if strings.Contains(line, f) {
				s.WriteString(line)
				break
			}
		}
	}
	ddl.Setvals = s.String()
	return ddl, true
}

func tableObject(name, typ, objSchema, body, schema, table string, quals []string, ownedSeq map[string]bool) bool {
	if objSchema != schema {
		return false
	}
	switch typ {
	case "TABLE", "ROW SECURITY":
		return name == table
	case "SEQUENCE", "SEQUENCE OWNED BY":
		return ownedSeq[schema+"\x00"+name]
	case "DEFAULT", "CONSTRAINT", "FK CONSTRAINT", "TRIGGER", "POLICY":
		return strings.HasPrefix(name, table+" ")
	case "COMMENT":
		return name == "TABLE "+table || strings.HasPrefix(name, "COLUMN "+table+".")
	case "INDEX":
		for _, q := range quals {
			if strings.Contains(body, " ON "+q+" ") || strings.Contains(body, " ON ONLY "+q+" ") {
				return true
			}
		}
	}
	return false
}

var bareIdentRe = regexp.MustCompile(`^[a-z_][a-z0-9_$]*$`)

// qualifiedForms is schema.table as pg_dump may write it: bare where the
// names allow, and quoted, which covers a name that is a keyword.
func qualifiedForms(schema, table string) []string {
	quote := func(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }
	ident := func(s string) []string {
		if bareIdentRe.MatchString(s) {
			return []string{s, quote(s)}
		}
		return []string{quote(s)}
	}
	var out []string
	for _, s := range ident(schema) {
		for _, t := range ident(table) {
			out = append(out, s+"."+t)
		}
	}
	return out
}

// splitQualified undoes quote_ident(schema) || '.' || quote_ident(name).
func splitQualified(q string) (schema, name string) {
	var parts []string
	var cur strings.Builder
	quoted := false
	for i := 0; i < len(q); i++ {
		c := q[i]
		switch {
		case c == '"' && quoted && i+1 < len(q) && q[i+1] == '"':
			cur.WriteByte('"')
			i++
		case c == '"':
			quoted = !quoted
		case c == '.' && !quoted:
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	parts = append(parts, cur.String())
	if len(parts) != 2 {
		return "", q
	}
	return parts[0], parts[1]
}
