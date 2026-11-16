package core

import (
	"testing"

	"enkv.sh/core/contract"
	catalog "enkv.sh/core/internal/testcatalog"
)

// The fixture has one supplied material and no generated work. The ordinary
// predecessor has one value page, one Recipient page, one access page, three
// support pages (output/receipt/index), and one index shard: at most7 children.
// Reserving two additional receipt/index pages gives at most9 after children.
// Every child profile is bounded by MaxRequiredSupportPageLength (2MiB).
func publicReplacementReservation(selected *StateSession, cell catalog.PublicReplacementCase) (budgetReservation, bool) {
	if selected == nil || selected.root.ChildCount > 7 || selected.root.ChildEncodedBytes > 7*contract.MaxRequiredSupportPageLength {
		return budgetReservation{}, false
	}
	charge, ok := operatorCLIReservation(selected, "keys-replace", 9, 9*contract.MaxRequiredSupportPageLength)
	if !ok {
		return budgetReservation{}, false
	}
	// Per provider call, the existing SDK owner allows at most three attempts.
	// Signing: resolve + qualify (two public calls), probe/binding/basis/final
	// signatures (four). Encryption: resolve + qualify (at most four public
	// calls), one source material decrypt, and one changed role KEK probe.
	// Recipient has one final signature and no successor private probe.
	kms := uint64(18)
	if cell.Change == "encryption" && cell.Target != "recipient" {
		kms = 21
	}
	if cell.Change == "both" {
		kms = 36
	}
	// Recovery signer qualification also checks provider-generated protection
	// metadata during both resolution and qualification (two extra public APIs).
	if cell.Target == "recovery" && cell.Change != "encryption" {
		kms += 6
	}
	delta := kms - 18
	charge.Requests += 2 * delta
	charge.BodyBytes += delta * operationBodyAllowance
	return charge, true
}

func publicReplacementReadReservation() budgetReservation {
	// The observer captures one HEAD and loads one complete selected image.
	// Six child passes bound initial loading plus generated/receipt/output/
	// publication relation scans and exact selected row rereads; eight fixed
	// reads cover HEAD/root/configuration. Each physical GET allows3 attempts.
	calls := uint64(3 * (6*9 + 8))
	return budgetReservation{Requests: 2 * calls, BodyBytes: calls * operationBodyAllowance}
}

// full_only: false
func TestPublicReplacementReservationsCoverExactPrivateRouteShapes(t *testing.T) {
	s := &StateSession{}
	s.root.ChildCount, s.root.ChildEncodedBytes = 7, 7*contract.MaxRequiredSupportPageLength
	for _, row := range []struct {
		target, change string
		calls          uint64
	}{{"authority", "signing", 276}, {"authority", "encryption", 279}, {"authority", "both", 294}, {"recovery", "both", 300}, {"recovery", "signing", 282}, {"recipient", "encryption", 276}} {
		cell := catalog.PublicReplacementCase{Target: row.target, Change: row.change, Authorizer: "authority"}
		charge, ok := publicReplacementReservation(s, cell)
		if !ok || charge.Requests != 2*row.calls || charge.BodyBytes != row.calls*operationBodyAllowance || charge.Objects != 10 || charge.ObjectBytes != 3*(9*contract.MaxRequiredSupportPageLength+contract.MaxRootLength)+3*contract.MaxHeadLength {
			t.Fatal("replacement reservation lost bounded graph terms", row, charge, ok)
		}
		for _, dimension := range []string{"requests", "bytes", "objects", "object-bytes"} {
			limits := liveLimits{Requests: charge.Requests, BodyBytes: charge.BodyBytes, Objects: charge.Objects, ObjectBytes: charge.ObjectBytes}
			switch dimension {
			case "requests":
				limits.Requests--
			case "bytes":
				limits.BodyBytes--
			case "objects":
				limits.Objects--
			case "object-bytes":
				limits.ObjectBytes--
			}
			budget := &runBudget{limits: limits}
			if budget.absorbChild(charge) || !budget.exhausted || budget.snapshot() != (budgetReservation{}) {
				t.Fatal("underfunded replacement entered child", dimension)
			}
		}
	}
}

func publicReplacementConsumeReservation(selected *StateSession) (budgetReservation, bool) {
	if selected == nil || selected.root.ChildCount == 0 || selected.root.ChildCount > 9 || selected.root.SecretCount != 1 || len(selected.adminIndex.Groups) != 0 {
		return budgetReservation{}, false
	}
	// At most three complete reconstruction attempts. Per attempt, allow the
	// initial child read plus generated, receipt, output, publication and owned
	// projection passes, and eight fixed HEAD/root/configuration reads. Every
	// physical reader permits three attempts. Six public/private API calls cover
	// Normal public qualification and the single selected material decrypt.
	calls := uint64(3*3)*(6*uint64(selected.root.ChildCount)+8) + 18
	return budgetReservation{Requests: 2 * calls, BodyBytes: calls * operationBodyAllowance}, true
}

// full_only: false
func TestPublicReplacementCompleteCellFitsRetainedFiniteAllowance(t *testing.T) {
	before := &StateSession{}
	before.root.ChildCount = 7
	before.root.ChildEncodedBytes = 7 * contract.MaxRequiredSupportPageLength
	replacement, ok := publicReplacementReservation(before, catalog.PublicReplacementCase{Target: "recovery", Change: "both", Authorizer: "authority", MaterialSource: "recovery"})
	if !ok {
		t.Fatal("maximum fixture replacement reservation refused")
	}
	after := &StateSession{}
	after.root.ChildCount = 9
	after.root.SecretCount = 1
	consume, ok := publicReplacementConsumeReservation(after)
	if !ok {
		t.Fatal("maximum fixture consume reservation refused")
	}
	read := publicReplacementReadReservation()
	// Four ordinary default children: init,set,apply,verification compare. Three
	// GET-only children: occupied repeat,cold query,fresh query. Four independent
	// complete GET-only opens: before,after,post-consumption,fresh. Two consumers
	// cover the hardest Recovery KEK/Recipient cell. The last52 request units
	// and170MiB cover bucket preflight, empty prefix scan and three independent
	// HEAD observations, each with the existing finite retry allowance. Eight
	// parse-only children (four independent opens,two output facts,two query
	// facts) each reserve1request/1byte and must emit only their joined footer.
	requests := uint64(4*128) + replacement.Requests + 3*read.Requests + 2*consume.Requests + 4*read.Requests + 52 + 8
	body := uint64(4*(16<<20)) + replacement.BodyBytes + 3*read.BodyBytes + 2*consume.BodyBytes + 4*read.BodyBytes + 170<<20 + 8
	if requests != 6080 || body != (14004<<20)+8 || requests > 8192 || body > 40<<30 {
		t.Fatal("complete replacement cell exceeds retained finite allowance", requests, body)
	}
	objects := uint64(16+16) + replacement.Objects
	objectBytes := uint64(2*(8<<20)) + replacement.ObjectBytes
	if objects != 42 || objects > 256 || objectBytes > 512<<20 {
		t.Fatal("replacement immutable allowance exceeds cleanup inventory bound", objects, objectBytes)
	}
	// The same budgets bound denied cells, which stop no later than final
	// authorization and perform no CAS/output. Existing cleanup owns each
	// captured create; an unknown typed result retains uncertainty instead of
	// converting this arithmetic into permission to delete unqualified keys.
}
