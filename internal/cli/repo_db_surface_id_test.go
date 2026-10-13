package cli

import "testing"

// An ad-hoc backup of the same database lands in the same repository
// whether or not the URL spells the default port, and whatever password it
// carries.
func TestTheAdHocRepositoryNamesTheDatabaseNotTheURL(t *testing.T) {
	for _, c := range []struct{ a, b string }{
		{"mysql://app:pw@db.internal/shop", "mysql://other:pw2@DB.internal:3306/shop"},
		{"mongodb://app:pw@db.internal/shop?authSource=admin", "mongodb://app:x@db.internal:27017/shop"},
		{"postgres://app:pw@db.internal/shop", "postgres://app:pw@db.internal:5432/shop?sslmode=require"},
	} {
		if repoDatabaseSurfaceID(c.a) != repoDatabaseSurfaceID(c.b) {
			t.Errorf("%s and %s name different repositories", c.a, c.b)
		}
	}
	if repoDatabaseSurfaceID("mysql://app:pw@db.internal/shop") == repoDatabaseSurfaceID("mysql://app:pw@db.internal/other") {
		t.Error("two databases name one repository")
	}
}
