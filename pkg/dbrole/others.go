package dbrole

import (
	"regexp"
	"sort"
	"strings"
)

// The same question for MySQL, MariaDB and MongoDB: what the account a
// surface connects as may change. A backup only reads.

// mysqlGrantRe is one line of SHOW GRANTS that grants privileges on an
// object: GRANT <privileges> ON <object> TO <account>. A line granting a role
// has no ON and is not matched.
var mysqlGrantRe = regexp.MustCompile(`(?i)^GRANT (.+?) ON (\S+) TO `)

// mysqlWrites are the privileges that change data or schema. TRIGGER and
// EVENT are not among them although they create objects: mysqldump needs both
// to read the triggers and events it backs up.
var mysqlWrites = map[string]bool{
	"ALL": true, "ALL PRIVILEGES": true, "INSERT": true, "UPDATE": true, "DELETE": true, "DROP": true,
	"CREATE": true, "ALTER": true, "INDEX": true, "CREATE VIEW": true, "CREATE ROUTINE": true,
	"ALTER ROUTINE": true, "SUPER": true,
}

// MySQLWrites names what an account's SHOW GRANTS lets it change, as
// "INSERT, UPDATE on `shop`.*", one entry per object, sorted. None means it
// changes nothing. A role's privileges are not in SHOW GRANTS without USING,
// so a role granted to the account is not looked into.
func MySQLWrites(grants []string) []string {
	var out []string
	for _, g := range grants {
		m := mysqlGrantRe.FindStringSubmatch(strings.TrimSpace(g))
		if m == nil {
			continue
		}
		var writes []string
		for _, p := range strings.Split(m[1], ",") {
			p = strings.ToUpper(strings.TrimSpace(p))
			if i := strings.IndexByte(p, '('); i >= 0 { // a column grant: SELECT (`a`)
				p = strings.TrimSpace(p[:i])
			}
			if mysqlWrites[p] {
				writes = append(writes, p)
			}
		}
		if len(writes) > 0 {
			out = append(out, strings.Join(writes, ", ")+" on "+m[2])
		}
	}
	sort.Strings(out)
	return out
}

// MongoRole is one role a MongoDB user holds, on a database.
type MongoRole struct {
	Role string `bson:"role"`
	DB   string `bson:"db"`
}

// mongoWrites are the built-in roles that can change data, users or the
// cluster. read, readAnyDatabase and backup cannot.
var mongoWrites = map[string]bool{
	"readWrite": true, "readWriteAnyDatabase": true, "dbOwner": true, "dbAdmin": true,
	"dbAdminAnyDatabase": true, "userAdmin": true, "userAdminAnyDatabase": true, "root": true,
	"restore": true, "clusterAdmin": true, "clusterManager": true, "hostManager": true, "__system": true,
}

// MongoWrites names the roles a user holds that can change something, as
// "readWrite on shop", sorted. A role of the user's own making is not
// judged: its privileges are not in the role's name.
func MongoWrites(roles []MongoRole) []string {
	var out []string
	for _, r := range roles {
		if mongoWrites[r.Role] {
			out = append(out, r.Role+" on "+r.DB)
		}
	}
	sort.Strings(out)
	return out
}
