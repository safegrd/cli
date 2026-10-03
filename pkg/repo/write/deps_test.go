package write_test

import (
	"os/exec"
	"strings"
	"testing"
)

// R6: the writer has no code path that reads back what it wrote. It must not
// depend on the half of the encryption that takes an identity, nor on the
// reader, the checker or the catalog.
func TestTheWriterCannotDecrypt(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "github.com/safegrd/cli/pkg/repo/write").CombinedOutput()
	if err != nil {
		t.Skipf("go list: %v %s", err, out)
	}
	for _, forbidden := range []string{"/pkg/repo/unseal", "/pkg/repo/read", "/pkg/repo/check", "/pkg/repo/catalog"} {
		for _, dep := range strings.Fields(string(out)) {
			if strings.HasSuffix(dep, forbidden) {
				t.Errorf("the writer depends on %s", dep)
			}
		}
	}
}
