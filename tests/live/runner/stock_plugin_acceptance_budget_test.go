package core

import (
	"fmt"
	"testing"

	"enkv.sh/core/contract"
	records "enkv.sh/core/internal/testrecords"
)

const stockImmutableBytes = 4 << 20
const stockPublicReadBodyAllowance = 3 << 20

func stockCommandReservation(input liveRunInput, phase string, args []string, priorReleases uint64) (budgetReservation, bool) {
	if input.StockRecovery != nil {
		if phase == "failed-writer-cleanup" {
			return budgetReservation(records.StockPluginRecoveryCommandReservation()), true
		}
		return budgetReservation{Requests: 128, BodyBytes: 16 << 20}, true
	}
	aws := input.Settings.Provider == "aws"
	if !aws && input.Settings.Provider != "gcp" || len(args) == 0 || priorReleases > 3 {
		return budgetReservation{}, false
	}
	q, observation, anchor := uint64(1), uint64(17), uint64(4)
	if aws {
		q, observation, anchor = 2, 18, 5
	}
	ordinaryObjects := uint64(20) + 5*priorReleases
	observation += 5 * priorReleases
	cold := 3 * (ordinaryObjects + 1 + observation)
	public := ordinaryObjects - 1 + anchor + observation
	var objects, extraReads, persists, selections, extra uint64
	var inboxes, inboxPersists, creates, retires uint64
	var configuration, publicRead bool
	operation := args[0]
	switch phase {
	case "a0-created", "a1-pending-a", "b2-created":
		if operation != "apply" {
			return budgetReservation{}, false
		}
		objects, extraReads, persists, selections = 32+5*priorReleases, 94+5*priorReleases, 9, 8
		extra = cold + 3*(49+26+10*(8+priorReleases)) + 6*12 + 3*3 + 18 + 3
		inboxes, inboxPersists, creates = 3, 6, 3
	case "exact-a-retired", "b-retired-a1", "final-generation-retired":
		if len(args) < 2 || operation != "generated" || args[1] != "retire" {
			return budgetReservation{}, false
		}
		objects, extraReads, persists, selections = 32+5*priorReleases, 40+5*priorReleases, 4, 3
		extra = cold + 3*(59+10+5*(6+priorReleases)) + 2*12 + 3 + 10 + 1
		inboxes, inboxPersists, retires = 1, 2, 3
	case "init":
		if operation != "init" {
			return budgetReservation{}, false
		}
		objects, extraReads, persists, selections = ordinaryObjects, observation, 1, 1
		kms := uint64(30)
		if aws {
			kms = 24
		}
		extra, configuration = cold+12+3+kms, true
	case "remove-generated":
		if operation != "apply" {
			return budgetReservation{}, false
		}
		objects, extraReads, persists, selections = ordinaryObjects, observation, 1, 1
		extra = cold + 3*(3+26*q+5*(3+priorReleases)) + 6
	case "plan":
		switch operation {
		case "apply":
			objects, extraReads, persists, selections = ordinaryObjects, observation, 1, 1
			extra = cold + 3*(3+26*q+5*(3+priorReleases)) + 6
		case "plan":
			extra, publicRead = public+2+3*q+(ordinaryObjects-1), true
		default:
			return budgetReservation{}, false
		}
	case "b-same-epoch-reused":
		if operation != "apply" {
			return budgetReservation{}, false
		}
		extra = cold + 3*(2+5*q) + 3
	case "missing-a-refused":
		if len(args) < 2 || operation != "generated" || args[1] != "retire" {
			return budgetReservation{}, false
		}
		extra = cold + 3*(59+10*q+5*(3+priorReleases))
	case "generated-list":
		if len(args) < 2 || operation != "generated" || args[1] != "list" {
			return budgetReservation{}, false
		}
		extra, publicRead = public, true
	case "materialize":
		if operation != "materialize" {
			return budgetReservation{}, false
		}
		extra = anchor + 3*(ordinaryObjects-1+observation) + 6 + 1
	case "manifest":
		if operation != "manifest" {
			return budgetReservation{}, false
		}
		extra, publicRead = public+2*q+2*(ordinaryObjects-1), true
	case "prepare":
		if operation != "prepare" {
			return budgetReservation{}, false
		}
		extra = 3*(2*ordinaryObjects+observation+anchor-1) + 9
	case "post-exit-reader":
		if operation != "plan" {
			return budgetReservation{}, false
		}
		extra, publicRead = public+2+2*q, true
	case "publish", "output-delete":
		if operation != "publish" {
			return budgetReservation{}, false
		}
		actions, kms, external, configurationReads := uint64(4), uint64(9), uint64(4), uint64(3)
		if aws {
			actions, kms, external = 10, 24, 18
		}
		if phase == "output-delete" {
			actions, kms, external, configurationReads = 2, 4, 4, 2
			if aws {
				actions, kms, external = 8, 16, 8
			}
		}
		objects, extraReads, persists, selections = ordinaryObjects, observation, 2*actions, 2*actions
		extra = (1+2*actions)*cold + 3*q*(1+configurationReads*actions) + kms + external
	case "set-secret":
		if operation != "set" {
			return budgetReservation{}, false
		}
	default:
		return budgetReservation{}, false
	}
	reservation := budgetReservation{Requests: extra, BodyBytes: extra * operationBodyAllowance,
		GeneratorCreates: creates, GeneratorRetires: retires}
	if publicRead {
		reservation.BodyBytes = extra * stockPublicReadBodyAllowance
	}
	if persists != 0 {
		candidate, ok := candidateStoreReservation(objects, stockImmutableBytes, objects+1+extraReads)
		if !ok {
			return budgetReservation{}, false
		}
		// Stock Store methods dispatch one service operation. Core owns all
		// retry and readback episodes already charged by the shared helper.
		reservation.Requests += selections*(candidate.Requests/2) + (persists-selections)*12*objects
		reservation.BodyBytes += selections*candidate.BodyBytes + (persists-selections)*12*objects*operationBodyAllowance
		// Successful reads use the exact reference length. Error responses use
		// at most64KiB; either path can consume one oversized-response probe.
		reservation.BodyBytes -= persists * 9 * objects * operationBodyAllowance
		reservation.BodyBytes += persists * 9 * (stockImmutableBytes + objects*((64<<10)+1))
		// A complete observation also loads root, children and HEAD. The image
		// has the same aggregate byte bound, even when every page is uncached.
		reservation.BodyBytes -= selections * 9 * (objects + 1) * operationBodyAllowance
		reservation.BodyBytes += selections * 9 * (stockImmutableBytes + (objects+1)*((64<<10)+1))
		reservation.Objects = persists * objects
		reservation.ObjectBytes = persists*3*stockImmutableBytes + selections*3*contract.MaxHeadLength
	}
	reservation.Objects += inboxes
	reservation.ObjectBytes += inboxPersists * 3 * uint64(contract.GeneratedResultRecordMaxLength)
	if configuration {
		reservation.Objects += 2
		reservation.ObjectBytes += 3 * contract.MaxStoreConfigurationLength
	}
	return reservation, true
}

// full_only: false
func TestStockCommandReservationsCoverFixedLifecycle(t *testing.T) {
	for _, provider := range []string{"aws", "gcp"} {
		t.Run(provider, func(t *testing.T) {
			input := liveRunInput{Settings: liveSettings{Provider: provider}}
			rows := []struct {
				phases               []string
				args                 []string
				priorReleases, count uint64
				aws, gcp             budgetReservation
			}{
				{[]string{"a0-created", "a1-pending-a"}, []string{"apply"}, 0, 2, budgetReservation{Requests: 13380, BodyBytes: 45070422888, Objects: 291, ObjectBytes: 116486538, GeneratorCreates: 3}, budgetReservation{Requests: 13377, BodyBytes: 45054694248, Objects: 291, ObjectBytes: 116486538, GeneratorCreates: 3}},
				{[]string{"b2-created"}, []string{"apply"}, 1, 1, budgetReservation{Requests: 14700, BodyBytes: 48030357093, Objects: 336, ObjectBytes: 116486538, GeneratorCreates: 3}, budgetReservation{Requests: 14697, BodyBytes: 48014628453, Objects: 336, ObjectBytes: 116486538, GeneratorCreates: 3}},
				{[]string{"exact-a-retired"}, []string{"generated", "retire"}, 0, 1, budgetReservation{Requests: 3995, BodyBytes: 10632235003, Objects: 129, ObjectBytes: 51477294, GeneratorRetires: 3}, budgetReservation{Requests: 3992, BodyBytes: 10616506363, Objects: 129, ObjectBytes: 51477294, GeneratorRetires: 3}},
				{[]string{"b-retired-a1"}, []string{"generated", "retire"}, 1, 1, budgetReservation{Requests: 4550, BodyBytes: 11911170358, Objects: 149, ObjectBytes: 51477294, GeneratorRetires: 3}, budgetReservation{Requests: 4547, BodyBytes: 11895441718, Objects: 149, ObjectBytes: 51477294, GeneratorRetires: 3}},
				{[]string{"final-generation-retired"}, []string{"generated", "retire"}, 2, 1, budgetReservation{Requests: 5105, BodyBytes: 13190105713, Objects: 169, ObjectBytes: 51477294, GeneratorRetires: 3}, budgetReservation{Requests: 5102, BodyBytes: 13174377073, Objects: 169, ObjectBytes: 51477294, GeneratorRetires: 3}},
				{[]string{"plan"}, []string{"apply"}, 2, 2, budgetReservation{Requests: 1326, BodyBytes: 4185195045, Objects: 30, ObjectBytes: 12779520}, budgetReservation{Requests: 1236, BodyBytes: 3713335845, Objects: 30, ObjectBytes: 12779520}},
				{[]string{"remove-generated"}, []string{"apply"}, 2, 1, budgetReservation{Requests: 1326, BodyBytes: 4185195045, Objects: 30, ObjectBytes: 12779520}, budgetReservation{Requests: 1236, BodyBytes: 3713335845, Objects: 30, ObjectBytes: 12779520}},
				{[]string{"init"}, []string{"init"}, 0, 1, budgetReservation{Requests: 759, BodyBytes: 2144403825, Objects: 22, ObjectBytes: 12791808}, budgetReservation{Requests: 753, BodyBytes: 2112946545, Objects: 22, ObjectBytes: 12791808}},
				{[]string{"b-same-epoch-reused"}, []string{"apply"}, 0, 1, budgetReservation{Requests: 156, BodyBytes: 817889280}, budgetReservation{Requests: 138, BodyBytes: 723517440}},
				{[]string{"b-same-epoch-reused"}, []string{"apply"}, 2, 1, budgetReservation{Requests: 216, BodyBytes: 1132462080}, budgetReservation{Requests: 198, BodyBytes: 1038090240}},
				{[]string{"missing-a-refused"}, []string{"generated", "retire"}, 0, 1, budgetReservation{Requests: 399, BodyBytes: 2091909120}, budgetReservation{Requests: 366, BodyBytes: 1918894080}},
				{[]string{"generated-list"}, []string{"generated", "list"}, 0, 4, budgetReservation{Requests: 42, BodyBytes: 132120576}, budgetReservation{Requests: 40, BodyBytes: 125829120}},
				{[]string{"generated-list"}, []string{"generated", "list"}, 1, 1, budgetReservation{Requests: 52, BodyBytes: 163577856}, budgetReservation{Requests: 50, BodyBytes: 157286400}},
				{[]string{"generated-list"}, []string{"generated", "list"}, 2, 2, budgetReservation{Requests: 62, BodyBytes: 195035136}, budgetReservation{Requests: 60, BodyBytes: 188743680}},
				{[]string{"generated-list"}, []string{"generated", "list"}, 3, 2, budgetReservation{Requests: 72, BodyBytes: 226492416}, budgetReservation{Requests: 70, BodyBytes: 220200960}},
				{[]string{"materialize"}, []string{"materialize"}, 0, 2, budgetReservation{Requests: 123, BodyBytes: 644874240}, budgetReservation{Requests: 119, BodyBytes: 623902720}},
				{[]string{"materialize"}, []string{"materialize"}, 1, 1, budgetReservation{Requests: 153, BodyBytes: 802160640}, budgetReservation{Requests: 149, BodyBytes: 781189120}},
				{[]string{"plan"}, []string{"plan"}, 2, 4, budgetReservation{Requests: 99, BodyBytes: 311427072}, budgetReservation{Requests: 94, BodyBytes: 295698432}},
				{[]string{"manifest"}, []string{"manifest"}, 2, 1, budgetReservation{Requests: 124, BodyBytes: 390070272}, budgetReservation{Requests: 120, BodyBytes: 377487360}},
				{[]string{"prepare"}, []string{"prepare"}, 2, 1, budgetReservation{Requests: 285, BodyBytes: 1494220800}, budgetReservation{Requests: 279, BodyBytes: 1462763520}},
				{[]string{"post-exit-reader"}, []string{"plan"}, 3, 1, budgetReservation{Requests: 78, BodyBytes: 245366784}, budgetReservation{Requests: 74, BodyBytes: 232783872}},
				{[]string{"set-secret"}, []string{"set"}, 2, 1, budgetReservation{}, budgetReservation{}},
				{[]string{"publish"}, []string{"publish"}, 2, 1, budgetReservation{Requests: 22005, BodyBytes: 60032297700, Objects: 600, ObjectBytes: 255590400}, budgetReservation{Requests: 8770, BodyBytes: 23845146920, Objects: 240, ObjectBytes: 102236160}},
				{[]string{"output-delete"}, []string{"publish"}, 2, 1, budgetReservation{Requests: 17583, BodyBytes: 47915737680, Objects: 480, ObjectBytes: 204472320}, budgetReservation{Requests: 4469, BodyBytes: 12362975380, Objects: 120, ObjectBytes: 51118080}},
			}
			var total budgetReservation
			var commands uint64
			for _, row := range rows {
				want := row.gcp
				if provider == "aws" {
					want = row.aws
				}
				for _, phase := range row.phases {
					t.Run(fmt.Sprintf("%s/%s/releases%d", phase, row.args[0], row.priorReleases), func(t *testing.T) {
						got, ok := stockCommandReservation(input, phase, row.args, row.priorReleases)
						if !ok || got != want {
							t.Fatalf("fixed stock reservation differs: got=%+v want=%+v", got, want)
						}
					})
				}
				total.Requests += row.count * want.Requests
				total.BodyBytes += row.count * want.BodyBytes
				total.Objects += row.count * want.Objects
				total.ObjectBytes += row.count * want.ObjectBytes
				total.GeneratorCreates += row.count * want.GeneratorCreates
				total.GeneratorRetires += row.count * want.GeneratorRetires
				commands += row.count
			}
			want := budgetReservation{Requests: 75200, BodyBytes: 233715235443, Objects: 1837, ObjectBytes: 708376104, GeneratorCreates: 9, GeneratorRetires: 9}
			if provider == "aws" {
				want = budgetReservation{Requests: 101976, BodyBytes: 307597389291, Objects: 2557, ObjectBytes: 1015084584, GeneratorCreates: 9, GeneratorRetires: 9}
			}
			if commands != 35 || total != want {
				t.Fatal("complete fixed command table differs", commands, total, want)
			}
		})
	}
}

// full_only: false
func TestStockCommandReservationRefusesUnprovedShapes(t *testing.T) {
	for _, row := range []struct {
		provider, phase string
		args            []string
	}{
		{"other", "init", []string{"init"}}, {"aws", "unknown", []string{"apply"}},
		{"gcp", "a0-created", nil}, {"aws", "a0-created", []string{"publish"}},
		{"gcp", "exact-a-retired", []string{"generated", "cleanup"}},
		{"aws", "plan", []string{"materialize"}}, {"gcp", "set-secret", []string{"publish"}},
		{"aws", "failed-writer-cleanup", []string{"generated", "cleanup"}},
	} {
		got, ok := stockCommandReservation(liveRunInput{Settings: liveSettings{Provider: row.provider}}, row.phase, row.args, 0)
		if ok || got != (budgetReservation{}) {
			t.Fatal("unproved stock command admitted", row.provider, row.phase, got)
		}
	}
	for _, priorReleases := range []uint64{4, ^uint64(0)} {
		got, ok := stockCommandReservation(liveRunInput{Settings: liveSettings{Provider: "gcp"}}, "generated-list", []string{"generated", "list"}, priorReleases)
		if ok || got != (budgetReservation{}) {
			t.Fatal("unbounded stock release backlog admitted", priorReleases, got)
		}
	}

}

// full_only: false
func TestStockRecoveryReservationsKeepOriginalAllowance(t *testing.T) {
	input := liveRunInput{Settings: liveSettings{Provider: "aws"}, StockRecovery: &records.StockPluginRecoveryInput{}}
	if got, ok := stockCommandReservation(input, "failed-writer-cleanup", []string{"generated", "cleanup"}, 0); !ok || got != budgetReservation(records.StockPluginRecoveryCommandReservation()) {
		t.Fatal("historical cleanup reservation changed", got)
	}
	want := budgetReservation{Requests: 128, BodyBytes: 16 << 20}
	if got, ok := stockCommandReservation(input, "generated-list", []string{"generated", "list"}, 0); !ok || got != want {
		t.Fatal("historical read reservation changed", got)
	}
}
