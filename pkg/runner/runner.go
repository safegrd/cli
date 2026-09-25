package runner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/safegrd/cli/pkg/crypto"
	"github.com/safegrd/cli/pkg/dump"
	"github.com/safegrd/cli/pkg/model"
	"github.com/safegrd/cli/pkg/storage"
)

// Verifier executes automated sandbox restore tests against stored snapshots.
type Verifier struct {
	storage     storage.StorageProvider
	serverURL   string
	serverToken string
}

// NewVerifier creates a Fire Drill restore verifier.
func NewVerifier(storage storage.StorageProvider, serverURL string) *Verifier {
	return &Verifier{
		storage:   storage,
		serverURL: serverURL,
	}
}

// SetServerToken configures the bearer token for authenticating verification reports.
func (v *Verifier) SetServerToken(token string) {
	v.serverToken = token
}

// RunFireDrill executes a complete test restore into an ephemeral target database,
// verifying table counts, row counts, extensions, and schema integrity.
func (v *Verifier) RunFireDrill(ctx context.Context, snapshotID, privateKey, sandboxTargetURL string) (*model.VerificationReport, error) {
	startTime := time.Now()

	// 1. Download metadata manifest
	meta, err := v.storage.DownloadMetadata(ctx, snapshotID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch snapshot metadata: %w", err)
	}
	rec := v.fetchRecord(ctx, snapshotID)

	if !meta.SurfaceType.IsDatabase() {
		return nil, fmt.Errorf("active sandbox Fire Drill requires a database snapshot; for %s use in-memory dry restore: safegrd verify --snapshot %s --dry-run", meta.SurfaceType, snapshotID)
	}
	kind := meta.SurfaceType
	if kind == "" {
		kind = model.SurfaceTypePostgres
	}
	if dump.SurfaceTypeOfURL(sandboxTargetURL) != kind {
		return nil, fmt.Errorf("snapshot %s is a %s snapshot; its sandbox must be a %s database too", snapshotID, meta.SurfaceType, meta.SurfaceType)
	}
	// Never restore over data: a sandbox that holds tables is not a sandbox,
	// and it may be production.
	if err := CheckSandboxEmpty(ctx, sandboxTargetURL); err != nil {
		return nil, err
	}

	report := &model.VerificationReport{
		VerificationID: "verif-" + uuid.New().String()[:8],
		SnapshotID:     snapshotID,
		NodeID:         meta.NodeID,
		SurfaceType:    model.SurfaceTypePostgres,
		DatabaseName:   meta.DatabaseName,
		StartedAt:      startTime,
		SandboxEngine:  "ephemeral-postgres-sandbox",
		Status:         model.VerificationStatusRunning,
	}
	if kind != model.SurfaceTypePostgres {
		report.SurfaceType, report.SandboxEngine = kind, "ephemeral-"+string(kind)+"-sandbox"
	}

	// 2. Download encrypted snapshot ciphertext
	cipherStream, err := v.storage.DownloadSnapshot(ctx, snapshotID)
	if err != nil {
		v.failEarly(ctx, report, startTime, fmt.Sprintf("failed downloading snapshot: %v", err))
		return report, nil
	}
	defer cipherStream.Close()

	// 3. Streaming Decryption Pipe
	plainReader, plainWriter := io.Pipe()
	decryptErrChan := make(chan error, 1)
	var decMetrics *crypto.StreamMetrics

	go func() {
		metrics, err := crypto.DecryptStream(cipherStream, plainWriter, privateKey)
		decMetrics = metrics
		if err != nil {
			_ = plainWriter.CloseWithError(err)
			decryptErrChan <- err
			return
		}
		_ = plainWriter.Close()
		decryptErrChan <- nil
	}()

	// 4. Restore into ephemeral sandbox database
	restorer := dump.NewRestorer(dump.EngineTypeNative, sandboxTargetURL)
	_, restoreErr := restorer.Restore(ctx, plainReader)
	// A restore that stops early leaves the rest of the stream unread, and
	// the decrypting goroutine blocked on it forever. Read it out, so the
	// digest is still checked and the restore's own error is the one reported.
	_, _ = io.Copy(io.Discard, plainReader)

	if err := <-decryptErrChan; err != nil {
		v.failEarly(ctx, report, startTime, fmt.Sprintf("decryption verification failed: %v", err))
		return report, nil
	}

	// 4b. Hold the decrypted stream to the digest recorded at backup time.
	if msg := v.checkDigests(report, meta, rec, decMetrics); msg != "" {
		v.failEarly(ctx, report, startTime, msg)
		return report, nil
	}

	if restoreErr != nil {
		v.failEarly(ctx, report, startTime, fmt.Sprintf("restore execution failed: %v", restoreErr))
		return report, nil
	}

	// 5. Count what the sandbox now holds, exactly.
	restoredMeta, err := inspectSandbox(ctx, sandboxTargetURL, meta)
	if err != nil {
		v.failEarly(ctx, report, startTime, fmt.Sprintf("sandbox inspection failed: %v", err))
		return report, nil
	}

	report.TablesRestored = restoredMeta.TotalTables
	report.RowsRestored = restoredMeta.TotalRows
	report.ExtensionsBooted = restoredMeta.Extensions

	// 6. Run Fire Drill Assertions
	allPassed := true

	// Assertion A: Table count match
	tableMatch := model.AssertionResult{
		Name:     "TableCountMatch",
		Expected: fmt.Sprintf("%d tables", meta.TotalTables),
		Actual:   fmt.Sprintf("%d tables", restoredMeta.TotalTables),
		Passed:   meta.TotalTables == restoredMeta.TotalTables,
	}
	if !tableMatch.Passed {
		allPassed = false
		tableMatch.Message = "Restored table count does not match snapshot metadata"
	}
	report.Assertions = append(report.Assertions, tableMatch)

	// Assertion B: Row count match
	rowMatch := model.AssertionResult{
		Name:     "RowCountMatch",
		Expected: fmt.Sprintf("%d rows", meta.TotalRows),
		Actual:   fmt.Sprintf("%d rows", restoredMeta.TotalRows),
		Passed:   meta.TotalRows == restoredMeta.TotalRows,
	}
	if !rowMatch.Passed {
		allPassed = false
		rowMatch.Message = "Restored total row count mismatch"
	}
	report.Assertions = append(report.Assertions, rowMatch)

	// Assertion C: Extension boot match
	extMatch := model.AssertionResult{
		Name:     "ExtensionBootCheck",
		Expected: fmt.Sprintf("%v", meta.Extensions),
		Actual:   fmt.Sprintf("%v", restoredMeta.Extensions),
		Passed:   len(restoredMeta.Extensions) >= len(meta.Extensions),
	}
	if !extMatch.Passed {
		allPassed = false
		extMatch.Message = "One or more database extensions failed to boot in sandbox"
	}
	report.Assertions = append(report.Assertions, extMatch)

	// Assertion D: the schema is one a restore rebuilds the database from.
	fidelity := dump.SchemaFidelity(meta)
	if !fidelity.Passed {
		allPassed = false
	}
	report.Assertions = append(report.Assertions, fidelity)

	report.CompletedAt = time.Now()
	report.DurationMs = drillMilliseconds(report.CompletedAt.Sub(startTime))

	if allPassed {
		report.Status = model.VerificationStatusPassed
		report.CertificateHash = computeCertificateHash(report)
	} else {
		report.Status = model.VerificationStatusFailed
		report.ErrorMessage = "One or more integrity assertions failed during Fire Drill"
	}

	// 7. Submit certificate report to SafeGrd remote server
	v.submitReport(ctx, report)

	return report, nil
}

// RunDryRestore downloads the encrypted snapshot from storage (S3 or local),
// decrypts it in memory with the Age private key, and verifies table counts, row counts,
// column counts, and extensions using the pure Go dry restore engine.
func (v *Verifier) RunDryRestore(ctx context.Context, snapshotID, privateKey string) (*model.VerificationReport, *dump.DryRestoreResult, error) {
	startTime := time.Now()

	// 1. Download metadata manifest from storage
	meta, err := v.storage.DownloadMetadata(ctx, snapshotID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch snapshot metadata: %w", err)
	}
	rec := v.fetchRecord(ctx, snapshotID)

	surface := meta.SurfaceType
	if surface == "" {
		surface = model.SurfaceTypePostgres
	}

	report := &model.VerificationReport{
		VerificationID: "verif-dry-" + uuid.New().String()[:8],
		SnapshotID:     snapshotID,
		NodeID:         meta.NodeID,
		SurfaceType:    surface,
		DatabaseName:   meta.DatabaseName,
		StartedAt:      startTime,
		SandboxEngine:  "in-memory-dry-restore",
		Status:         model.VerificationStatusRunning,
	}

	// 2. Download encrypted snapshot ciphertext from storage
	cipherStream, err := v.storage.DownloadSnapshot(ctx, snapshotID)
	if err != nil {
		v.failEarly(ctx, report, startTime, fmt.Sprintf("failed downloading snapshot from storage: %v", err))
		return report, nil, nil
	}
	defer cipherStream.Close()

	// 3. Streaming Decryption Pipe
	plainReader, plainWriter := io.Pipe()
	decryptErrChan := make(chan error, 1)
	var decMetrics *crypto.StreamMetrics

	go func() {
		metrics, err := crypto.DecryptStream(cipherStream, plainWriter, privateKey)
		decMetrics = metrics
		if err != nil {
			_ = plainWriter.CloseWithError(err)
			decryptErrChan <- err
			return
		}
		_ = plainWriter.Close()
		decryptErrChan <- nil
	}()

	// 4. Run In-Memory Dry Restore Inspector based on Surface Type
	var (
		dryResult   *dump.DryRestoreResult
		fileResult  *dump.FileDryRestoreResult
		emailResult *dump.EmailDryRestoreResult
		dryErr      error
	)

	switch surface {
	case model.SurfaceTypeFiles:
		fileInspector := dump.NewFileRestorer()
		fileResult, dryErr = fileInspector.InspectFileArchive(ctx, plainReader, meta)
	case model.SurfaceTypeEmail:
		emailInspector := dump.NewEmailRestorer()
		emailResult, dryErr = emailInspector.InspectEmailArchive(ctx, plainReader, meta)
	case model.SurfaceTypeMySQL:
		dryResult, dryErr = dump.InspectMySQLArchive(ctx, plainReader)
	case model.SurfaceTypeMongoDB:
		dryResult, dryErr = dump.InspectMongoArchive(ctx, plainReader)
	case model.SurfaceTypeSQLite:
		dryResult, dryErr = dump.InspectSQLiteArchive(ctx, plainReader)
	default:
		dryInspector := dump.NewDryRestorer()
		dryResult, dryErr = dryInspector.InspectArchive(ctx, plainReader)
	}
	_, _ = io.Copy(io.Discard, plainReader) // as above: an inspection may stop early

	// Check decryption status
	if decErr := <-decryptErrChan; decErr != nil {
		report.Status = model.VerificationStatusFailed
		report.ErrorMessage = fmt.Sprintf("Age private key decryption failed: %v", decErr)
		report.Assertions = append(report.Assertions, model.AssertionResult{
			Name:     "DecryptionIntegrity",
			Passed:   false,
			Expected: "valid Age private key matching recipient public key",
			Actual:   decErr.Error(),
			Message:  "Cryptographic signature check or decryption failed",
		})
		v.failEarly(ctx, report, startTime, report.ErrorMessage)
		return report, dryResult, nil
	}

	report.Assertions = append(report.Assertions, model.AssertionResult{
		Name:     "DecryptionIntegrity",
		Passed:   true,
		Expected: "Age X25519 payload authenticates and decrypts cleanly",
		Actual:   "Ciphertext decrypted successfully with private identity key",
	})

	// Hold the decrypted stream to the digest recorded at backup time.
	if msg := v.checkDigests(report, meta, rec, decMetrics); msg != "" {
		v.failEarly(ctx, report, startTime, msg)
		return report, dryResult, nil
	}

	if dryErr != nil {
		v.failEarly(ctx, report, startTime, fmt.Sprintf("dry restore archive inspection error: %v", dryErr))
		return report, dryResult, nil
	}

	// Transfer dry assertions and stats
	report.CompletedAt = time.Now()
	report.DurationMs = drillMilliseconds(report.CompletedAt.Sub(startTime))

	switch surface {
	case model.SurfaceTypeFiles:
		if fileResult != nil {
			report.TotalItems = fileResult.TotalFiles
			report.TotalContainers = fileResult.TotalDirectories
			report.TablesRestored = fileResult.TotalDirectories
			report.RowsRestored = fileResult.TotalFiles
			report.Assertions = append(report.Assertions, fileResult.Assertions...)

			if fileResult.Passed {
				report.Status = model.VerificationStatusPassed
				report.CertificateHash = computeCertificateHash(report)
			} else {
				report.Status = model.VerificationStatusFailed
				report.ErrorMessage = fileResult.ErrorMessage
				if report.ErrorMessage == "" {
					report.ErrorMessage = "One or more assertions failed during file archive dry restore"
				}
			}
		} else {
			report.Status = model.VerificationStatusFailed
			report.ErrorMessage = "no file dry restore inspection results generated"
		}
	case model.SurfaceTypeEmail:
		if emailResult != nil {
			report.TotalItems = emailResult.TotalEmails
			report.TotalContainers = emailResult.TotalFolders
			report.TablesRestored = emailResult.TotalFolders
			report.RowsRestored = emailResult.TotalEmails
			report.Assertions = append(report.Assertions, emailResult.Assertions...)

			if emailResult.Passed {
				report.Status = model.VerificationStatusPassed
				report.CertificateHash = computeCertificateHash(report)
			} else {
				report.Status = model.VerificationStatusFailed
				report.ErrorMessage = emailResult.ErrorMessage
				if report.ErrorMessage == "" {
					report.ErrorMessage = "One or more assertions failed during email archive dry restore"
				}
			}
		} else {
			report.Status = model.VerificationStatusFailed
			report.ErrorMessage = "no email dry restore inspection results generated"
		}
	default:
		if dryResult != nil {
			report.TotalItems = dryResult.TotalRows
			report.TotalContainers = dryResult.TotalTables
			report.TablesRestored = dryResult.TotalTables
			report.RowsRestored = dryResult.TotalRows
			report.ExtensionsBooted = dryResult.Extensions
			report.Assertions = append(report.Assertions, dryResult.Assertions...)

			if dryResult.Passed {
				report.Status = model.VerificationStatusPassed
				report.CertificateHash = computeCertificateHash(report)
			} else {
				report.Status = model.VerificationStatusFailed
				report.ErrorMessage = dryResult.ErrorMessage
				if report.ErrorMessage == "" {
					report.ErrorMessage = "One or more assertions failed during in-memory dry restore"
				}
			}
		} else {
			report.Status = model.VerificationStatusFailed
			report.ErrorMessage = "no dry restore inspection results generated"
		}
	}

	// Unconditional: submitReport says so when there is no server, rather than
	// a drill quietly existing only on this screen.
	v.submitReport(ctx, report)

	return report, dryResult, nil
}

// failEarly records a drill that failed before its assertions ran (the
// snapshot could not be read, decrypted or restored) and reports it, so a
// drill that could not even start is on the record as a failure rather than
// missing from it. It carries a certificate hash like any other report,
// because the next record links to it.
func (v *Verifier) failEarly(ctx context.Context, report *model.VerificationReport, started time.Time, msg string) {
	report.Status = model.VerificationStatusFailed
	report.ErrorMessage = msg
	report.CompletedAt = time.Now()
	report.DurationMs = drillMilliseconds(report.CompletedAt.Sub(started))
	report.CertificateHash = computeCertificateHash(report)
	v.submitReport(ctx, report)
}

func (v *Verifier) submitReport(ctx context.Context, report *model.VerificationReport) {
	if v.serverURL == "" {
		fmt.Fprintf(os.Stderr, "\n[!] Not recorded: no remote server configured for this run.\n"+
			"    The verification above is real; nothing outside this machine knows it happened.\n")
		return
	}
	if v.serverToken == "" {
		fmt.Fprintf(os.Stderr, "\n[!] NOT RECORDED: no server_token in this config, so the remote server cannot be told.\n"+
			"    The verification above is real; nothing outside this machine knows it happened.\n")
		return
	}

	data, err := json.Marshal(report)
	if err != nil {
		return
	}

	req, err := http.NewRequestWithContext(ctx, "POST", v.serverURL+"/api/v1/verifications", bytes.NewReader(data))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if v.serverToken != "" {
		req.Header.Set("Authorization", "Bearer "+v.serverToken)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n[!] NOT RECORDED: could not reach %s: %v\n"+
			"    The verification itself is valid and shown above, but the remote server\n"+
			"    has no record of it.\n", v.serverURL, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusPaymentRequired {
		var body struct {
			Error string `json:"error"`
		}
		msg := "Fire Drills are not included on your plan, so this drill was not recorded."
		if json.NewDecoder(io.LimitReader(resp.Body, 4<<10)).Decode(&body) == nil && body.Error != "" {
			msg = body.Error
		}
		fmt.Fprintf(os.Stderr, "\n[!] Not recorded by the remote server: %s\n", msg)
		return
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		var body struct {
			Error string `json:"error"`
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		_ = json.Unmarshal(raw, &body)
		detail := body.Error
		if detail == "" {
			detail = strings.TrimSpace(string(raw))
		}
		fmt.Fprintf(os.Stderr, "\n[!] NOT RECORDED: %s rejected the verification: HTTP %d %s\n"+
			"    The drill itself is valid and shown above.\n",
			v.serverURL, resp.StatusCode, detail)
	}
}

// computeCertificateHash is the value the attestation chain links against:
// the next record's PrevHash is the previous record's CertificateHash.
func computeCertificateHash(r *model.VerificationReport) string {
	payload := fmt.Sprintf("CERT:%s:%s:%s:%d:%d:%d",
		r.VerificationID, r.SnapshotID, r.NodeID,
		r.TablesRestored, r.RowsRestored, r.CompletedAt.Unix())
	h := sha256.Sum256([]byte(payload))
	return "cert_sg_" + hex.EncodeToString(h[:])
}

// legacyDigestExplanation distinguishes a snapshot written before the digest
// fix from an actually corrupt one.
//
// Older CLI versions recorded the ciphertext digest in Sha256Checksum.
// If the manifest digest matches the ciphertext, this is a legacy snapshot
// and the backup payload is sound.
func legacyDigestExplanation(decMetrics *crypto.StreamMetrics, expected, source string) string {
	if decMetrics.EncryptedSha256 != "" && decMetrics.EncryptedSha256 == expected {
		return fmt.Sprintf(
			"this snapshot was written before 2026-09-21, when the manifest recorded the digest of the "+
				"ciphertext (%s) rather than of the data. The backup itself decrypted cleanly and is intact; "+
				"it cannot be digest-verified against the restored stream. Snapshots taken since then can be",
			expected)
	}
	return fmt.Sprintf("cryptographic digest mismatch: raw sha256 (%s) != %s sha256 (%s)",
		decMetrics.RawSha256, source, expected)
}

// inspectSandbox counts every table a drill restored into its sandbox.
func inspectSandbox(ctx context.Context, sandboxURL string, meta *model.SnapshotMetadata) (*model.SnapshotMetadata, error) {
	if dump.IsSQLiteURL(sandboxURL) {
		path, err := dump.SQLitePath(sandboxURL)
		if err != nil {
			return nil, err
		}
		counts, err := dump.SQLiteCountRows(ctx, path)
		if err != nil {
			return nil, err
		}
		restored := &model.SnapshotMetadata{SurfaceType: model.SurfaceTypeSQLite, DatabaseName: meta.DatabaseName}
		for _, t := range meta.TableStats {
			restored.TableStats = append(restored.TableStats, model.TableStat{Schema: t.Schema, TableName: t.TableName, RowCount: counts[t.TableName]})
		}
		restored.CalculateTotals()
		return restored, nil
	}
	if dump.IsMongoURL(sandboxURL) {
		client, db, err := dump.OpenMongo(ctx, sandboxURL)
		if err != nil {
			return nil, err
		}
		defer func() { _ = client.Disconnect(context.Background()) }()
		counts, err := dump.MongoCountDocuments(ctx, db, meta)
		if err != nil {
			return nil, err
		}
		restored := &model.SnapshotMetadata{SurfaceType: model.SurfaceTypeMongoDB, DatabaseName: meta.DatabaseName}
		for _, t := range meta.TableStats {
			restored.TableStats = append(restored.TableStats, model.TableStat{Schema: t.Schema, TableName: t.TableName, RowCount: counts[t.TableName]})
		}
		restored.CalculateTotals()
		return restored, nil
	}
	if dump.IsMySQLURL(sandboxURL) {
		db, err := dump.OpenMySQL(sandboxURL)
		if err != nil {
			return nil, err
		}
		defer db.Close()
		counts, err := dump.MySQLCountRows(ctx, db, meta)
		if err != nil {
			return nil, err
		}
		restored := &model.SnapshotMetadata{SurfaceType: model.SurfaceTypeMySQL, DatabaseName: meta.DatabaseName}
		for _, t := range meta.TableStats {
			restored.TableStats = append(restored.TableStats, model.TableStat{Schema: t.Schema, TableName: t.TableName, RowCount: counts[t.TableName]})
		}
		restored.CalculateTotals()
		return restored, nil
	}
	inspector, err := dump.NewInspector(sandboxURL)
	if err != nil {
		return nil, fmt.Errorf("connecting to restored sandbox failed: %w", err)
	}
	defer inspector.Close()
	restored, err := inspector.Inspect(ctx, meta.DatabaseName)
	if err != nil {
		return nil, err
	}
	if err := inspector.CountRowsExactly(ctx, restored); err != nil {
		return nil, err
	}
	return restored, nil
}

// drillMilliseconds rounds a drill's duration up to whole milliseconds. A drill
// of a small tree finishes in microseconds, and a signed report that says it
// took 0 ms reads as a drill that never ran.
func drillMilliseconds(d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	return int64((d + time.Millisecond - 1) / time.Millisecond)
}
