package compositionfull

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

var ErrPublicQueryResult = errors.New("public query result rendering refused")

// JSON strings use at most six bytes per UTF-8 source byte. Configuration
// fields, including repeated target policies, are charged by their complete
// canonical image: sixteen bytes per encoded byte pays both escaping and its
// closed field framing. An absent policy object uses its containing target or
// binding's fixed ID/framing allowance. Compact administrative indexes pay
// 2,048 bytes per fixed group plus sixteen per logical byte for pages, spans,
// row summaries, publication order and u16 relation indexes (at most six JSON
// bytes each, versus two canonical bytes).
//
// A coordinate uses at most 27,728 JSON bytes; a current target 6,362; a marker
// 20,746. The allowances below include their separators and all fields at owner
// widths, sixfold string escaping and the longest boolean. All blocker rows
// together use at most 60,416 bytes. Complete release records use at most 633
// bytes; their extra 512 allowance supplements the generated owner's original
// 512-byte release projection account. Metadata rows without memberships use
// at most 1,946 bytes and registry rows 1,858. Each membership costs 67 bytes.
const publicQueryOutputLimit = generatedResultOutputLimit + 512*core.GeneratedResultAttemptLimit +
	16*uint64(contract.MaxOutputConfigurationBytes) +
	16*uint64(contract.MaxChildPages)*contract.MaxRequiredSupportPageLength + 2048*65535 +
	32768*uint64(contract.MaxPublicationCoordinates) + 7168*uint64(contract.MaxOutputTargets) +
	1024*uint64(contract.MaxPublicationCoordinates) + 32768*uint64(contract.MaxPublicationMarkers) +
	4096*uint64(contract.CryptoMaxValueEntries+contract.CryptoMaxRecipients) +
	67*uint64(contract.CryptoMaxMemberships) + 8192*uint64(2*contract.MutationReceiptWindowLimit) + 65536

// The native source refusal adds one bounded singleton to the complete compact
// account above. Its generated-family base already includes the single 1024-byte
// Store location reserve. Every nested plugin/canonical image is scalar Base64; the
// closed public query schema has at most twelve structural levels.
const publicQueryCompactOutputLimit = publicQueryOutputLimit + 2048

func queryHexID(id contract.ID) string { return hex.EncodeToString(id[:]) }

type queryObject struct {
	w     *resultStreamWriter
	first bool
	human bool
	depth int
}

func queryBegin(w *resultStreamWriter) *queryObject {
	w.text("{")
	return &queryObject{w: w, first: true}
}
func (o *queryObject) key(name string) {
	if !o.first {
		o.w.text(",")
	}
	o.first = false
	o.w.value(name)
	o.w.text(":")
}
func (o *queryObject) field(name string, value any) {
	if o.human {
		if name == "form" {
			return
		}
		if name == "schema" {
			if _, ok := value.(string); ok {
				return
			}
		}
		o.line(queryHumanLabel(name) + ": ")
		o.w.value(value)
		o.w.text("\n")
		return
	}
	o.key(name)
	o.w.value(value)
}
func (o *queryObject) id(name string, value contract.ID) { o.field(name, hex.EncodeToString(value[:])) }
func (o *queryObject) begin() *queryObject {
	if o.human {
		return &queryObject{w: o.w, human: true, depth: o.depth}
	}
	return queryBegin(o.w)
}
func (o *queryObject) value(value any) {
	if o.human {
		o.field("value", value)
		return
	}
	o.w.value(value)
}
func (o *queryObject) line(s string) {
	o.w.text(strings.Repeat("  ", o.depth) + s)
}
func queryHumanLabel(name string) string {
	name = strings.ReplaceAll(name, "_", " ")
	if len(name) > 0 && name[0] >= 'a' && name[0] <= 'z' {
		name = string(name[0]-'a'+'A') + name[1:]
	}
	return name
}
func (o *queryObject) object(name string, emit func(*queryObject)) {
	if o.human {
		o.line(queryHumanLabel(name) + ":\n")
		emit(&queryObject{w: o.w, human: true, depth: o.depth + 1})
		return
	}
	o.key(name)
	child := o.begin()
	emit(child)
	child.end()
}
func (o *queryObject) array(name string, n int, emit func(int)) {
	if o.human {
		o.line(fmt.Sprintf("%s: %d rows\n", queryHumanLabel(name), n))
		o.depth++
		for i := 0; i < n && o.w.err == nil; i++ {
			o.line(fmt.Sprintf("Row %d:\n", i+1))
			o.depth++
			emit(i)
			o.depth--
		}
		o.depth--
		return
	}
	o.key(name)
	o.w.text("[")
	for i := 0; i < n && o.w.err == nil; i++ {
		if i != 0 {
			o.w.text(",")
		}
		emit(i)
	}
	o.w.text("]")
}
func (o *queryObject) end() {
	if !o.human {
		o.w.text("}")
	}
}
func queryIDs(o *queryObject, name string, ids []contract.ID) {
	o.array(name, len(ids), func(i int) { o.value(hex.EncodeToString(ids[i][:])) })
}
func queryIndexes(o *queryObject, name string, indexes []uint16) {
	o.array(name, len(indexes), func(i int) { o.value(indexes[i]) })
}
func queryDescriptor(o *queryObject, name string, d contract.GeneratorDescriptor) {
	o.object(name, func(q *queryObject) { q.field("count", d.Count); q.field("length", d.Length); q.id("digest", d.Digest) })
}
func queryObservation(o *queryObject, v core.PublicObservation) {
	o.id("domain_id", v.DomainID)
	o.id("head_revision_id", v.HeadRevisionID)
	o.id("snapshot_id", v.SnapshotID)
	o.id("root_digest", v.RootDigest)
}
func queryDomainWarnings(o *queryObject, v core.PublicDomainWarnings) {
	o.field("orphan_generated_effect", v.OrphanGeneratedEffect)
	o.field("late_destructive_effect", v.LateDestructiveEffect)
	o.field("publication_order_value", v.PublicationOrderValue)
	o.field("discarded_exact_evidence", v.DiscardedExactEvidence)
	o.field("possible_store_garbage", v.PossibleStoreGarbage)
}

func writePublicQuery(ctx context.Context, out io.Writer, base core.PublicQueryResult, human bool, payloadName string, emit func(*queryObject), warnings func(*resultStreamWriter), sourceFailure *ConfigurationSourceFailure, locations ...*resultStoreLocation) error {
	return writePublicQueryDelivery(ctx, out, base, human, payloadName, emit, warnings, nil, sourceFailure, locations...)
}

func writePublicQueryDelivery(ctx context.Context, out io.Writer, base core.PublicQueryResult, human bool, payloadName string, emit func(*queryObject), warnings func(*resultStreamWriter), delivery *GCPlanDelivery, sourceFailure *ConfigurationSourceFailure, locations ...*resultStoreLocation) error {
	if ctx == nil || out == nil || !validQuerySourceFailure(base, sourceFailure) {
		return ErrPublicQueryResult
	}
	if sourceFailure != nil && delivery != nil && (delivery.PlanCreated || delivery.PlanSynced || delivery.PlanReadback) {
		return ErrPublicQueryResult
	}
	var location *resultStoreLocation
	if len(locations) != 0 {
		location = locations[0]
	}
	if !location.valid(base.DomainID, base.Result) || location != nil && emit == nil {
		return ErrPublicQueryResult
	}
	if _, ok := administrativeCoreResult(base.Result); !ok {
		return ErrPublicQueryResult
	}
	identity := generatedID(base.RequestIdentity)
	if p := base.PreAdmission; p != nil {
		if !base.RequestIdentity.IsZero() || payloadName != "none" || emit != nil || p.RequestNonce != base.RequestID || p.Code != string(base.FailureReason) {
			return ErrPublicQueryResult
		}
		value, ok := preAdmissionIdentity(base.Operation, base.OperationID, p)
		if !ok {
			return ErrPublicQueryResult
		}
		identity = value
	} else if base.RequestIdentity.IsZero() && (!base.OperationID.IsZero() || payloadName != "none" || emit != nil) {
		return ErrPublicQueryResult
	}
	write := func(w *resultStreamWriter) {
		if human {
			writePublicQueryHuman(w, base, emit, warnings, delivery, sourceFailure, location)
			return
		}
		q := queryBegin(w)
		q.field("schema", "ProductResult/v1")
		if location != nil {
			q.field("store_location", location.fields())
		}
		q.field("operation_kind", base.Operation)
		q.field("state_result", base.StateResult)
		q.field("effect_summary", "not-applicable")
		q.field("output_summary", "not-applicable")
		q.field("request_id", generatedID(base.RequestID))
		q.field("operation_id", generatedID(base.OperationID))
		q.field("request_identity", identity)
		q.field("replay_identity", "none")
		q.field("domain_id", generatedID(base.DomainID))
		q.field("failure_reason", base.FailureReason)
		if sourceFailure != nil {
			q.field("source_failure", sourceFailure)
		}
		if delivery != nil {
			q.field("delivery", *delivery)
		}
		r, _ := administrativeCoreResult(base.Result)
		q.field("result", r)
		evidence := "unavailable"
		if base.Result.Evidence == core.AuthenticatedClosure {
			evidence = "canonical"
		}
		q.field("evidence_ceiling", evidence)
		q.array("effects", 0, nil)
		q.array("outputs", 0, nil)
		q.array("duties", 0, nil)
		q.array("hazards", 0, nil)
		q.field("capsule_policy", "none")
		q.field("operation_payload", payloadName)
		if emit == nil {
			q.field("payload", nil)
		} else {
			q.object("payload", emit)
		}
		q.end()
		w.text("\n")
	}
	if !human {
		return writeReadableResultJSON(ctx, out, publicQueryCompactOutputLimit, ErrPublicQueryResult, write)
	}
	count := &resultStreamWriter{ctx: ctx, limit: publicQueryHumanOutputLimit, limitError: ErrPublicQueryResult}
	write(count)
	if count.err != nil {
		return errors.Join(ErrPublicQueryResult, count.err)
	}
	stream := &resultStreamWriter{ctx: ctx, out: out, limit: count.n, limitError: ErrPublicQueryResult}
	write(stream)
	if stream.err != nil {
		return stream.err
	}
	if stream.n != count.n {
		return ErrPublicQueryResult
	}
	return nil
}

func PublicQueryExitCode(r core.PublicQueryResult) int {
	switch r.StateResult {
	case core.PublicQuerySuccess:
		return 0
	case core.PublicQueryUnavailable, core.PublicQueryContention:
		return 3
	}
	return 2
}
