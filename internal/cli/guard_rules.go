package cli

import (
	"regexp"
)

// A destructiveRule names one kind of command that can destroy data a backup
// would bring back. Hooks match a shell command against these before an AI
// agent or a script runs it, and take a snapshot first when one matches.
type destructiveRule struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
	re      *regexp.Regexp
}

// destructiveRules is the list `safegrd guard --list` prints and
// `guard --matches` checks. The text of a command is matched as a whole, so a
// statement inside quotes (psql -c "DROP TABLE users") matches, and so does
// one that only mentions it (grep "DROP TABLE"). A false match costs one extra
// snapshot; a missed one costs the data.
var destructiveRules = compileRules([]destructiveRule{
	{Name: "SQL DROP", Pattern: `(?i)\bdrop\s+(table|database|schema|view|materialized\s+view|index|sequence|function|procedure|trigger|type|extension|owned|role|user)\b`},
	{Name: "SQL TRUNCATE", Pattern: `(?i)\btruncate\s+(table\s+)?["'\w]`},
	{Name: "SQL DELETE without WHERE", Pattern: `(?i)\bdelete\s+from\s+[\w."]+\s*(;|$|["'])`},
	{Name: "dropdb", Pattern: `(^|[\s;&|(])dropdb\s`},
	{Name: "terraform destroy", Pattern: `\b(terraform|tofu)\s+(.*\s)?destroy\b|\b(terraform|tofu)\s+apply\s+(.*\s)?-destroy\b`},
	{Name: "prisma migrate reset", Pattern: `\bprisma\s+migrate\s+reset\b`},
	{Name: "prisma db push --force-reset", Pattern: `\bprisma\s+db\s+push\b.*--force-reset\b`},
	{Name: "supabase db reset", Pattern: `\bsupabase\s+db\s+reset\b`},
	{Name: "rails db:drop / db:reset", Pattern: `\b(rails|rake)\s+(.*\s)?db:(drop|reset|schema:load|purge)\b`},
	{Name: "django flush", Pattern: `\bmanage\.py\s+(flush|reset_db)\b`},
})

func compileRules(rules []destructiveRule) []destructiveRule {
	for i := range rules {
		rules[i].re = regexp.MustCompile(rules[i].Pattern)
	}
	return rules
}

// matchDestructive returns the rule a command matches, or nil.
func matchDestructive(command string) *destructiveRule {
	for i := range destructiveRules {
		if destructiveRules[i].re.MatchString(command) {
			return &destructiveRules[i]
		}
	}
	return nil
}
