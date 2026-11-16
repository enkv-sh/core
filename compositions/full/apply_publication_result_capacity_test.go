package compositionfull

import (
	"math"
	"testing"

	"enkv.sh/core"
)

// full_only: false
func TestApplyPublicationStageCountsItsCompleteWrapper(t *testing.T) {
	// These literals contain no stage result bytes. Their lengths are derived
	// directly from the closed response grammar, independently of the writer.
	const evaluated = `{"stage":"evaluated","reason":null,"result":}`
	const humanEvaluated = "publication:\nstage: evaluated\nreason: null\nresult:\n"
	if len(evaluated) != 45 || len(humanEvaluated) != 51 {
		t.Fatal("independent framing derivation changed")
	}
	stage := core.ApplyPublicationStage{Stage: "evaluated", Result: &core.PublicPublicationResult{}}
	for _, test := range []struct {
		name   string
		human  bool
		prefix uint64
	}{
		{"json", false, 45},
		{"human", true, 51},
	} {
		t.Run(test.name, func(t *testing.T) {
			const body = uint64(108068919 + 2048)
			publicationMaximum := body + test.prefix
			got, err := applyPublicationStageSize(stage, body, test.human)
			if err != nil || got != publicationMaximum {
				t.Fatalf("complete stage=%d, want %d: %v", got, publicationMaximum, err)
			}
			if _, err := applyPublicationStageSize(stage, body+1, test.human); err == nil {
				t.Fatal("one-over complete publication stage was accepted")
			}
			if _, err := applyPublicationStageSize(stage, math.MaxUint64, test.human); err == nil {
				t.Fatal("stage byte addition overflow was accepted")
			}
		})
	}
}

// full_only: false
func TestApplyPublicationUnstartedStageCountsEveryClosedReason(t *testing.T) {
	for _, test := range []struct {
		reason     string
		jsonBytes  uint64
		humanBytes uint64
	}{
		{"apply-incomplete", 63, 68},
		{"selection-unavailable", 68, 73},
		{"selection-conflict", 65, 70},
		{"deadline-expired", 63, 68},
	} {
		t.Run(test.reason, func(t *testing.T) {
			jsonLiteral := `{"stage":"unstarted","reason":"` + test.reason + `","result":null}`
			humanLiteral := "publication:\nstage: unstarted\nreason: " + test.reason + "\nresult: null\n"
			if uint64(len(jsonLiteral)) != test.jsonBytes || uint64(len(humanLiteral)) != test.humanBytes {
				t.Fatal("independent unstarted framing derivation changed")
			}
			stage := core.ApplyPublicationStage{Stage: "unstarted", Reason: test.reason}
			for _, format := range []struct {
				human bool
				want  uint64
			}{{false, test.jsonBytes}, {true, test.humanBytes}} {
				got, err := applyPublicationStageSize(stage, 0, format.human)
				if err != nil || got != format.want {
					t.Fatalf("unstarted stage=%d, want %d: %v", got, format.want, err)
				}
				if _, err := applyPublicationStageSize(stage, 1, format.human); err == nil {
					t.Fatal("unstarted stage accepted a hidden result body")
				}
			}
		})
	}
}

// full_only: false
func TestApplyPublicationCompleteBodyBoundsIncludeStageAndFinalFraming(t *testing.T) {
	// Apply's bound is the existing independently specified generated renderer
	// account. Publication includes its wrapper; JSON adds the outer object + LF.
	// Apply pays 3,081 complete 3,428-byte human diagnostics. Publication
	// pays 33 bytes for executable cleanup and 22 for local pair cleanup.
	const applyMaximum = uint64(65536 + 8192*(1408+128) + 2*471 + 32*(256*(2097152-75)) + 116 + 3081*3428)
	const publicationMaximum = uint64(6*16777216 + 1024*(1024+3*2048) + 65536 + 33 + 22)
	const outerJSON = `{"schema":"ApplyPublicationResult/v1","apply":,"publication":}` + "\n"
	if applyMaximum != 17202465958 || publicationMaximum != 108068919 || len(outerJSON) != 63 {
		t.Fatal("independent complete-response derivation changed")
	}
	stage := core.ApplyPublicationStage{Stage: "evaluated", Result: &core.PublicPublicationResult{}}
	for _, test := range []struct {
		name    string
		human   bool
		wrapper uint64
		framing uint64
		maximum uint64
	}{
		{"json", false, 45, 63, 17310534940},
		{"human", true, 51, 256, 17310535133},
	} {
		t.Run(test.name, func(t *testing.T) {
			publication, err := applyPublicationStageSize(stage, publicationMaximum-test.wrapper, test.human)
			if err != nil {
				t.Fatal(err)
			}
			got, err := applyPublicationResultSize(applyMaximum, publication, test.framing, test.maximum)
			if err != nil || got != test.maximum {
				t.Fatalf("complete response=%d, want %d: %v", got, test.maximum, err)
			}
			for _, sizes := range [][4]uint64{
				{applyMaximum + 1, publication, test.framing, test.maximum},
				{applyMaximum, publication + 1, test.framing, test.maximum},
				{applyMaximum, publication, test.framing + 1, test.maximum},
				{applyMaximum, publication, test.framing, test.maximum - 1},
			} {
				if _, err := applyPublicationResultSize(sizes[0], sizes[1], sizes[2], sizes[3]); err == nil {
					t.Fatal("one-over complete response was accepted", sizes)
				}
			}
		})
	}
}
