package dump

import "testing"

// s3://* is every bucket the key lists: the bucket comes back empty, and the
// root prints the same way, so a surface over a whole project round-trips.
func TestAnObjectStoreRootNamesOneBucketOrEveryBucket(t *testing.T) {
	for _, c := range []struct {
		root           string
		bucket, prefix string
		ok             bool
	}{
		{"s3://uploads", "uploads", "", true},
		{"s3://uploads/tenant/a/", "uploads", "tenant/a", true},
		{"s3://*", "", "", true},
		{"s3://*/public", "", "public", true},
		{"s3://", "", "", false},
		{"/var/www", "", "", false},
	} {
		bucket, prefix, ok := ParseObjectStoreRoot(c.root)
		if bucket != c.bucket || prefix != c.prefix || ok != c.ok {
			t.Errorf("%s: %q %q %v, want %q %q %v", c.root, bucket, prefix, ok, c.bucket, c.prefix, c.ok)
		}
		if ok {
			if got := (ObjectStoreSource{Bucket: bucket, Prefix: prefix}).Root(); got != c.root && got+"/" != c.root {
				t.Errorf("%s round-trips as %s", c.root, got)
			}
		}
	}
	if (ObjectStoreSource{}).Root() != AllBucketsRoot {
		t.Errorf("an empty bucket is not %s", AllBucketsRoot)
	}
}
