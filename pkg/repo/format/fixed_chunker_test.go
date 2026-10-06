package format

import (
	"testing"
	"time"
)

// An epoch the WordPress plugin writes declares fixed chunks. Readers accept
// it, and nothing else named "fixed" passes.
func TestAnEpochOfFixedChunksValidates(t *testing.T) {
	opened := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	e := Epoch{
		Format: FormatName, Version: Version, EpochID: "e202610-0a1b2c3d", SurfaceID: "wordpress",
		OpenedAt: opened, PlannedEnd: opened.AddDate(0, 1, 0), Reason: ReasonFirst, TMidDays: 7, OpeningTier: TierBase,
		OpeningRetainUntil: opened.AddDate(0, 1, 10), LaterRetainUntil: opened.AddDate(0, 1, 7),
		Recipient: "age1ue4ukzl0yhp5lgz4mkayfmvyyr7zvgfkwsnlatst53kaw0xvtsrq3nwla9", Chunker: FixedChunker, PackTargetBytes: DefaultPackTarget,
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("an epoch of fixed chunks: %v", err)
	}
	e.Chunker = ChunkerParams{Algorithm: "fixed", Min: 1, Avg: 1 << 20, Max: 1 << 20}
	if err := e.Validate(); err == nil {
		t.Fatal("a fixed chunker of another size validated")
	}
}
