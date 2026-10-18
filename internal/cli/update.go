package cli

// Updating the daemon's own binary from the remote server's console.
//
// install.sh lays a host out as
//
//	<root>/versions/<version>/safegrd
//	<root>/current  -> versions/<version>
//	<root>/previous -> versions/<version it replaced>
//	/usr/local/bin/safegrd -> <root>/current/safegrd
//
// and only a binary running from that layout updates itself. The remote server
// names a release; the daemon downloads it from the release page (or
// daemon.updates_url), and installs it only when checksums.txt is signed by a
// key compiled into this binary, the archive matches it, the version is newer
// than this one, and the new binary passes `daemon run --self-test` with this
// daemon's own arguments. Then `current` is moved and the daemon execs it: the
// same process, so the service manager sees no restart.
//
// A release that does not check in with the remote server within two passes,
// or starts three times without doing so, moves `current` back and execs the
// release before it. The console can also ask for that release back; the host
// goes back only to the binary it already holds, and downloads nothing.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/release"
)

// defaultUpdatesURL is where releases are downloaded from unless
// daemon.updates_url names a mirror.
const defaultUpdatesURL = "https://github.com/safegrd/cli/releases/download"

// stateFormat is the version of the daemon's state files this release writes.
// A release that changes them in a way the release before cannot read raises
// it, and the console then offers no way back past it.
const stateFormat = 1

// Bounds on an update.
const (
	updateCheckInPasses = 2
	updateMaxStarts     = 3
	updateSelfTestLimit = 2 * time.Minute
	updateFetchLimit    = 15 * time.Minute
	updateMaxArchive    = 300 << 20
	updateFetchBackoff  = time.Hour
	updateFetchMaxWait  = 24 * time.Hour
)

// selfTestPassed is what `daemon run --self-test` prints, with the version.
const selfTestPassed = "self-test passed"

// hostUpdates is the running daemon's updater; nil outside `daemon run`.
var hostUpdates *updater

// updateRecord is update.json in the state directory: what must survive the
// exec into another release.
type updateRecord struct {
	// Pending is a switch the new release has not yet confirmed by checking
	// in with the remote server.
	Pending *pendingSwitch `json:"pending,omitempty"`
	// PreviousFormat is the stateFormat of the release `previous` points at.
	PreviousFormat int `json:"previous_format,omitempty"`

	Staged       string    `json:"staged,omitempty"`
	FetchVersion string    `json:"fetch_version,omitempty"`
	FetchError   string    `json:"fetch_error,omitempty"`
	FetchFails   int       `json:"fetch_fails,omitempty"`
	NextFetch    time.Time `json:"next_fetch,omitempty"`

	Failed       string     `json:"failed,omitempty"`
	FailedReason string     `json:"failed_reason,omitempty"`
	Change       string     `json:"change,omitempty"`
	ChangeFrom   string     `json:"change_from,omitempty"`
	ChangeTo     string     `json:"change_to,omitempty"`
	ChangeAt     *time.Time `json:"change_at,omitempty"`
	Handled      string     `json:"handled,omitempty"`
	Refused      string     `json:"refused,omitempty"`
}

type pendingSwitch struct {
	From   string    `json:"from"`
	To     string    `json:"to"`
	At     time.Time `json:"at"`
	Starts int       `json:"starts"`
}

// updater holds what the daemon knows about updating itself.
type updater struct {
	mode        string
	installedBy string
	layout      *hostLayout
	stateDir    string
	baseURL     string
	args        []string // this process's arguments after the program name
	// beforeExec releases what the old process holds (the daemon's lock),
	// which an exec would otherwise keep in its name.
	beforeExec func()

	rec          updateRecord
	latest       string
	request      *model.UpdateRequest
	passesSince  int
	confirmedNow bool
}

// newUpdater reads where this binary lives and what update.json holds.
func newUpdater(mode, baseURL, stateDir string, args []string) (*updater, error) {
	switch mode {
	case "":
		mode = model.UpdatesConsole
	case model.UpdatesConsole, model.UpdatesOff:
	default:
		return nil, fmt.Errorf("daemon.updates %q in the config is not %q or %q", mode, model.UpdatesConsole, model.UpdatesOff)
	}
	if baseURL == "" {
		baseURL = defaultUpdatesURL
	}
	u := &updater{mode: mode, stateDir: stateDir, baseURL: strings.TrimRight(baseURL, "/"), args: args}
	u.layout, u.installedBy = detectLayout()
	if b, err := os.ReadFile(u.recordPath()); err == nil {
		if err := json.Unmarshal(b, &u.rec); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: %s does not parse (%v); starting it again.\n", u.recordPath(), err)
			u.rec = updateRecord{}
		}
	}
	return u, nil
}

func (u *updater) recordPath() string { return filepath.Join(u.stateDir, "update.json") }

func (u *updater) save() {
	b, _ := json.MarshalIndent(&u.rec, "", "  ")
	tmp := u.recordPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err == nil {
		err = os.Rename(tmp, u.recordPath())
		if err == nil {
			return
		}
	}
	fmt.Fprintf(os.Stderr, "Warning: could not save %s; an update in progress may not be undone on its own.\n", u.recordPath())
}

// start runs once when the daemon starts: it counts the starts of a release
// not yet confirmed, and goes back to the release before after too many.
func (u *updater) start() {
	p := u.rec.Pending
	if p == nil {
		return
	}
	if normVersion(Version) != p.To {
		// Not the release the switch went to: something else moved it.
		u.rec.Pending = nil
		u.save()
		return
	}
	p.Starts++
	u.save()
	if p.Starts > updateMaxStarts {
		u.rollBack(fmt.Sprintf("it started %d times without checking in with the remote server", p.Starts-1))
	}
}

// report is the update state sent with a heartbeat; nil from a single pass.
func (u *updater) report(tick time.Duration) *model.UpdateStatus {
	if u == nil || tick == 0 {
		return nil
	}
	st := &model.UpdateStatus{
		Running: normVersion(Version), Mode: u.mode, InstalledBy: u.installedBy,
		Staged: u.rec.Staged, FetchVersion: u.rec.FetchVersion, FetchError: u.rec.FetchError,
		Failed: u.rec.Failed, FailedReason: u.rec.FailedReason,
		Change: u.rec.Change, ChangeFrom: u.rec.ChangeFrom, ChangeTo: u.rec.ChangeTo, ChangeAt: u.rec.ChangeAt,
		Handled: u.rec.Handled, Refused: u.rec.Refused,
	}
	if u.layout != nil {
		st.Blocked = u.blocked()
		st.Previous = u.layout.link("previous")
		st.NoRevert = st.Previous != "" && u.rec.PreviousFormat < stateFormat
	}
	return st
}

// blocked is why this host cannot update now, or "".
func (u *updater) blocked() string {
	if normVersion(Version) == "dev" || parseVersionOK(Version) != nil {
		return "this is a development build (" + Version + "), which does not update itself"
	}
	if err := u.layout.writable(); err != nil {
		if errors.Is(err, os.ErrPermission) {
			return fmt.Sprintf("the daemon runs as a user who cannot write %s. Run it as the user who installed safegrd, or re-run the installer as that user", u.layout.root)
		}
		return fmt.Sprintf("the daemon cannot write %s (%v). Its service predates updates from the console: restart the daemon if the installer has just updated the service, or run sudo safegrd daemon install", u.layout.root, err)
	}
	return ""
}

// heard takes what a heartbeat answered: the newest release and any request.
// The first answer a new release gets confirms the switch to it.
func (u *updater) heard(resp *model.HeartbeatResponse) {
	if u == nil || resp == nil {
		return
	}
	u.latest = normVersion(resp.LatestCLIVersion)
	u.request = resp.UpdateRequest
	if p := u.rec.Pending; p != nil && p.To == normVersion(Version) {
		u.rec.Pending = nil
		u.confirmedNow = true
		u.save()
	}
}

// afterPass runs between passes, when no surface is being backed up or
// drilled: it rolls back a release that has not checked in, acts on a
// request from the console, or downloads the newest release ahead of time.
func (u *updater) afterPass(ctx context.Context, lockDir string) {
	if u == nil {
		return
	}
	if u.confirmedNow {
		u.confirmedNow = false
		fmt.Printf("Running %s, which checked in with the remote server.\n", Version)
	}
	if p := u.rec.Pending; p != nil && p.To == normVersion(Version) {
		u.passesSince++
		if u.passesSince >= updateCheckInPasses {
			u.rollBack(fmt.Sprintf("it did not check in with the remote server within %d passes", updateCheckInPasses))
		}
		return
	}
	if u.layout == nil || u.mode == model.UpdatesOff {
		return
	}
	if why := u.blocked(); why != "" {
		return
	}
	if req := u.request; req != nil && req.ID != "" && req.ID != u.rec.Handled {
		if busy := otherSafegrdRunning(lockDir); busy != "" {
			fmt.Printf("Update requested in the console; waiting for %s to finish.\n", busy)
			return
		}
		var err error
		switch req.Action {
		case model.UpdateActionInstall:
			err = u.install(ctx, req)
		case model.UpdateActionRevert:
			err = u.revert(req)
		default:
			err = fmt.Errorf("this release does not know the request %q", req.Action)
		}
		// Reached only when nothing was exec'd.
		u.rec.Handled, u.rec.Refused = req.ID, ""
		if err != nil {
			u.rec.Refused = err.Error()
			fmt.Fprintf(os.Stderr, "Error: the update the console asked for was not made: %v\n", err)
		}
		u.save()
		return
	}
	if u.latest != "" && model.IsVersionOutdated(Version, u.latest) && u.rec.Staged != u.latest && time.Now().After(u.rec.NextFetch) {
		if err := u.stage(ctx, u.latest); err != nil {
			u.rec.FetchVersion, u.rec.FetchError = u.latest, err.Error()
			u.rec.FetchFails++
			wait := updateFetchBackoff << min(u.rec.FetchFails-1, 5)
			u.rec.NextFetch = time.Now().Add(min(wait, updateFetchMaxWait))
			fmt.Fprintf(os.Stderr, "Warning: could not download safegrd %s: %v. Trying again after %s.\n",
				u.latest, err, u.rec.NextFetch.UTC().Format("2006-01-02 15:04 UTC"))
		} else {
			u.rec.Staged, u.rec.FetchVersion, u.rec.FetchError, u.rec.FetchFails = u.latest, "", "", 0
			u.rec.NextFetch = time.Time{}
			fmt.Printf("Downloaded and checked safegrd %s. Install it from the console.\n", u.latest)
		}
		u.save()
	}
}

// stage downloads release v into its versions directory and checks it.
func (u *updater) stage(ctx context.Context, v string) error {
	dir := u.layout.versionDir(v)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, updateFetchLimit)
	defer cancel()
	archive := release.ArchiveName(v, runtime.GOOS, runtime.GOARCH)
	files := []string{release.ChecksumsFile, archive}
	if release.Signed() {
		files = append(files, release.SignatureFile)
	}
	for _, f := range files {
		if err := u.download(ctx, v, f, filepath.Join(dir, f)); err != nil {
			return err
		}
	}
	return u.verifyStaged(v)
}

// verifyStaged checks the files stage downloaded, again, from disk.
func (u *updater) verifyStaged(v string) error {
	dir := u.layout.versionDir(v)
	sums, err := os.ReadFile(filepath.Join(dir, release.ChecksumsFile))
	if err != nil {
		return err
	}
	var sig []byte
	if release.Signed() {
		if sig, err = os.ReadFile(filepath.Join(dir, release.SignatureFile)); err != nil {
			return err
		}
	}
	archive := release.ArchiveName(v, runtime.GOOS, runtime.GOARCH)
	return release.Verify(sums, sig, filepath.Join(dir, archive), archive)
}

func (u *updater) download(ctx context.Context, v, file, dest string) error {
	url := fmt.Sprintf("%s/v%s/%s", u.baseURL, v, file)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", UserAgent())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	tmp := dest + ".part"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(resp.Body, updateMaxArchive+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > updateMaxArchive {
		err = fmt.Errorf("%s is larger than any safegrd release", url)
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dest)
}

// install switches to the release req names and execs it. It returns only
// when it did not.
func (u *updater) install(ctx context.Context, req *model.UpdateRequest) error {
	v := normVersion(req.Version)
	if parseVersionOK(v) != nil {
		return fmt.Errorf("%q is not a release version", req.Version)
	}
	if !model.IsVersionOutdated(Version, v) {
		return fmt.Errorf("this host runs %s; an update goes only to a newer release, and %s is not", Version, v)
	}
	fmt.Printf("Installing safegrd %s, as asked in the console.\n", v)
	if u.rec.Staged == v {
		// Checked again from disk; a copy that no longer passes is
		// downloaded afresh rather than refused on every request.
		if err := u.verifyStaged(v); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: the downloaded safegrd %s no longer passes its checks (%v); downloading it again.\n", v, err)
			u.rec.Staged = ""
			os.RemoveAll(u.layout.versionDir(v))
		}
	}
	if u.rec.Staged != v {
		if err := u.stage(ctx, v); err != nil {
			u.save()
			return fmt.Errorf("downloading %s: %w", v, err)
		}
		u.rec.Staged = v
	}
	dir := u.layout.versionDir(v)
	bin := filepath.Join(dir, "safegrd")
	archive := filepath.Join(dir, release.ArchiveName(v, runtime.GOOS, runtime.GOARCH))
	if err := release.ExtractBinary(archive, release.ArchiveDir(v, runtime.GOOS, runtime.GOARCH), bin); err != nil {
		return err
	}
	if err := selfTest(ctx, bin, u.args, v); err != nil {
		return fmt.Errorf("safegrd %s did not pass its self-test on this host: %w", v, err)
	}
	from := normVersion(Version)
	oldPrev, oldFormat := u.layout.link("previous"), u.rec.PreviousFormat
	now := time.Now().UTC()
	u.rec.Pending = &pendingSwitch{From: from, To: v, At: now}
	u.rec.PreviousFormat = stateFormat
	u.rec.Change, u.rec.ChangeFrom, u.rec.ChangeTo, u.rec.ChangeAt = model.UpdateChangeInstalled, from, v, &now
	u.rec.Handled, u.rec.Refused, u.rec.Staged = req.ID, "", ""
	if u.rec.Failed == v {
		u.rec.Failed, u.rec.FailedReason = "", ""
	}
	u.save()
	undo := func() {
		u.rec.Pending, u.rec.PreviousFormat = nil, oldFormat
		u.rec.Change, u.rec.ChangeFrom, u.rec.ChangeTo, u.rec.ChangeAt = "", "", "", nil
		_ = u.layout.setLink("current", from) // what it pointed at a moment ago; the error is the one returned
		if oldPrev != "" {
			_ = u.layout.setLink("previous", oldPrev)
		} else {
			u.layout.removeLink("previous")
		}
	}
	if err := u.layout.setLink("previous", from); err != nil {
		undo()
		return err
	}
	if err := u.layout.setLink("current", v); err != nil {
		undo()
		return err
	}
	u.layout.prune(v, from)
	fmt.Printf("Switched to safegrd %s (from %s). Restarting into it.\n", v, from)
	err := u.exec()
	undo()
	return fmt.Errorf("could not start %s: %w", v, err)
}

// revert goes back to the release `previous` points at, asked in the console.
func (u *updater) revert(req *model.UpdateRequest) error {
	prev := u.layout.link("previous")
	if prev == "" {
		return errors.New("this host holds no earlier release to go back to")
	}
	if u.rec.PreviousFormat < stateFormat {
		return fmt.Errorf("%s changed the daemon's state in a way %s cannot read, so this host cannot go back to it", Version, prev)
	}
	from := normVersion(Version)
	if err := u.layout.setLink("current", prev); err != nil {
		return err
	}
	u.layout.removeLink("previous")
	now := time.Now().UTC()
	u.rec.Change, u.rec.ChangeFrom, u.rec.ChangeTo, u.rec.ChangeAt = model.UpdateChangeReverted, from, prev, &now
	u.rec.Handled, u.rec.Refused, u.rec.Pending = req.ID, "", nil
	u.save()
	fmt.Printf("Going back to safegrd %s (from %s), as asked in the console.\n", prev, from)
	err := u.exec()
	_ = u.layout.setLink("current", from) // back as it was; the exec's error is the one returned
	_ = u.layout.setLink("previous", prev)
	u.rec.Change, u.rec.ChangeFrom, u.rec.ChangeTo, u.rec.ChangeAt = "", "", "", nil
	return fmt.Errorf("could not start %s: %w", prev, err)
}

// rollBack leaves a release that did not check in for the one before it.
func (u *updater) rollBack(why string) {
	failed := normVersion(Version)
	prev := ""
	if u.layout != nil {
		prev = u.layout.link("previous")
	}
	fmt.Fprintf(os.Stderr, "Error: safegrd %s is being left: %s.\n", failed, why)
	u.rec.Pending = nil
	u.rec.Failed, u.rec.FailedReason = failed, why
	if prev == "" {
		u.rec.FailedReason += "; there is no earlier release on this host to go back to"
		u.save()
		return
	}
	if err := u.layout.setLink("current", prev); err != nil {
		u.rec.FailedReason += fmt.Sprintf("; going back to %s failed: %v", prev, err)
		u.save()
		return
	}
	u.layout.removeLink("previous")
	now := time.Now().UTC()
	u.rec.Change, u.rec.ChangeFrom, u.rec.ChangeTo, u.rec.ChangeAt = model.UpdateChangeRolledBack, failed, prev, &now
	u.save()
	fmt.Fprintf(os.Stderr, "Going back to safegrd %s.\n", prev)
	if err := u.exec(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: could not start %s: %v. Restart the daemon; it runs %s now.\n", prev, err, prev)
	}
}

// exec replaces this process with the binary `current` points at, with the
// same arguments and environment.
func (u *updater) exec() error {
	bin := filepath.Join(u.layout.root, "current", "safegrd")
	if u.beforeExec != nil {
		u.beforeExec()
	}
	return execImage(bin, u.args)
}

// execImage is execSelf; a test replaces it to see what would have run.
var execImage = execSelf

// selfTest runs bin as this daemon was run, with --self-test, and checks it
// reports version v.
func selfTest(ctx context.Context, bin string, args []string, v string) error {
	ctx, cancel := context.WithTimeout(ctx, updateSelfTestLimit)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, append(append([]string{}, args...), "--self-test")...)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		if len(text) > 500 {
			text = text[len(text)-500:]
		}
		return fmt.Errorf("%v: %s", err, text)
	}
	if want := selfTestPassed + " " + v; !strings.Contains(text, want) {
		return fmt.Errorf("it printed %q, not %q", lastLine(text), want)
	}
	return nil
}

func lastLine(s string) string {
	if i := strings.LastIndex(s, "\n"); i >= 0 {
		return s[i+1:]
	}
	return s
}

// otherSafegrdRunning names a lock another live safegrd process holds in the
// daemon's lock directory, or "".
func otherSafegrdRunning(lockDir string) string {
	entries, err := os.ReadDir(lockDir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".lock") || name == "daemon.lock" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(lockDir, name))
		if err != nil {
			continue
		}
		var l LockInfo
		if json.Unmarshal(b, &l) == nil && l.PID != os.Getpid() && isPIDAlive(l.PID) {
			return fmt.Sprintf("PID %d (%s)", l.PID, strings.TrimSuffix(name, ".lock"))
		}
	}
	return ""
}

// hostLayout is install.sh's versions directory.
type hostLayout struct {
	root string
}

// detectLayout says where this binary lives: in the versions layout, or
// installed some other way.
func detectLayout() (*hostLayout, string) {
	exe, err := os.Executable()
	if err != nil {
		return nil, model.InstalledByOther
	}
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	versions := filepath.Dir(filepath.Dir(exe))
	if filepath.Base(versions) == "versions" && filepath.Base(exe) == "safegrd" {
		root := filepath.Dir(versions)
		if fi, err := os.Lstat(filepath.Join(root, "current")); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			return &hostLayout{root: root}, model.InstalledByInstaller
		}
	}
	switch {
	case strings.Contains(exe, "/Cellar/") || strings.Contains(exe, "/homebrew/"):
		return nil, model.InstalledByHomebrew
	case fileExists("/.dockerenv") || fileExists("/run/.containerenv") || os.Getenv("KUBERNETES_SERVICE_HOST") != "":
		return nil, model.InstalledByContainer
	}
	return nil, model.InstalledByOther
}

func (l *hostLayout) versionDir(v string) string {
	return filepath.Join(l.root, "versions", v)
}

// link is the version a link in root points at, or "".
func (l *hostLayout) link(name string) string {
	t, err := os.Readlink(filepath.Join(l.root, name))
	if err != nil {
		return ""
	}
	v := filepath.Base(t)
	if !fileExists(filepath.Join(l.versionDir(v), "safegrd")) {
		return ""
	}
	return v
}

// setLink points root/name at versions/v, in one rename.
func (l *hostLayout) setLink(name, v string) error {
	tmp := filepath.Join(l.root, fmt.Sprintf(".%s.%d", name, os.Getpid()))
	os.Remove(tmp)
	if err := os.Symlink(filepath.Join("versions", v), tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(l.root, name)); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func (l *hostLayout) removeLink(name string) {
	_ = os.Remove(filepath.Join(l.root, name)) // a link left behind names a release still on disk
}

// writable reports whether the daemon can change the layout.
func (l *hostLayout) writable() error {
	f, err := os.CreateTemp(l.root, ".write-check-")
	if err != nil {
		return err
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}

// prune removes every release but the ones named, and any the links name.
func (l *hostLayout) prune(keep ...string) {
	k := map[string]bool{l.link("current"): true, l.link("previous"): true}
	for _, v := range keep {
		k[v] = true
	}
	entries, err := os.ReadDir(filepath.Join(l.root, "versions"))
	if err != nil {
		return
	}
	var gone []string
	for _, e := range entries {
		if !k[e.Name()] {
			if err := os.RemoveAll(l.versionDir(e.Name())); err == nil {
				gone = append(gone, e.Name())
			}
		}
	}
	sort.Strings(gone)
	if len(gone) > 0 {
		fmt.Printf("Removed releases no longer needed: %s.\n", strings.Join(gone, ", "))
	}
}

func normVersion(v string) string {
	return strings.TrimPrefix(strings.TrimSpace(v), "v")
}

// parseVersionOK reports whether v is a plain x.y.z release version.
func parseVersionOK(v string) error {
	parts := strings.Split(normVersion(v), ".")
	if len(parts) != 3 {
		return fmt.Errorf("%q is not x.y.z", v)
	}
	for _, p := range parts {
		if p == "" || strings.Trim(p, "0123456789") != "" {
			return fmt.Errorf("%q is not x.y.z", v)
		}
	}
	return nil
}

// daemonSelfTest is `daemon run --self-test`: what a daemon about to switch to
// this release runs it with. It reads the config, the flags and the daemon's
// state as `daemon run` would, takes no lock and starts nothing.
func daemonSelfTest(stateDir, intervalStr string) error {
	if intervalStr != "" {
		if d, err := time.ParseDuration(intervalStr); err != nil || d <= 0 {
			return fmt.Errorf("--interval %q is not a positive duration such as 5m or 1h", intervalStr)
		}
	} else if cfg.Daemon.Interval != "" {
		if d, err := time.ParseDuration(cfg.Daemon.Interval); err != nil || d <= 0 {
			return fmt.Errorf("daemon.interval %q in the config is not a positive duration such as 5m or 1h", cfg.Daemon.Interval)
		}
	}
	if _, err := newUpdater(cfg.Daemon.Updates, cfg.Daemon.UpdatesURL, stateDir, nil); err != nil {
		return err
	}
	for _, name := range []string{"daemon_state.json", "update.json"} {
		b, err := os.ReadFile(filepath.Join(stateDir, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		var v map[string]any
		if err := json.Unmarshal(b, &v); err != nil {
			return fmt.Errorf("%s does not parse: %w", name, err)
		}
	}
	if b, err := os.ReadFile(filepath.Join(stateDir, "daemon_state.json")); err == nil {
		var st DaemonState
		if err := json.Unmarshal(b, &st); err != nil {
			return fmt.Errorf("daemon_state.json cannot be read by this release: %w", err)
		}
	}
	fmt.Printf("%s %s (%d surfaces)\n", selfTestPassed, normVersion(Version), len(cfg.Surfaces))
	return nil
}

// updatesWords is how the daemon says at start whether it updates itself.
func updatesWords(u *updater) string {
	switch {
	case u.mode == model.UpdatesOff:
		return "off (daemon.updates: off)"
	case u.layout == nil:
		return "not from the console: this binary was not installed by install.sh (" + u.installedBy + ")"
	}
	if why := u.blocked(); why != "" {
		return "not possible: " + why
	}
	return "from the console (" + u.layout.root + ")"
}

// notifies reports whether the daemon should print that a release is out: not
// when it fetches releases itself and says so.
func (u *updater) notifies() bool {
	return u == nil || u.layout == nil || u.mode == model.UpdatesOff
}
