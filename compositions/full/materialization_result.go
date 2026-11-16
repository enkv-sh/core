package compositionfull

import (
	"context"
	"errors"
	"fmt"
	"io"

	"enkv.sh/core"
	"enkv.sh/core/contract"
)

var ErrMaterializationResult = errors.New("materialization result rendering refused")

// Six bytes cover each escaped UTF-8 byte. Entry framing and its two fixed IDs
// fit in 1024 bytes; the fixed header, both paths and public binding are charged
// separately. Human output selects native delivery facts and entry names
// within the same account.
const materializationCompactResultLimit = uint64(16384+12*contract.MaterializationMaxPath+12*contract.KMSBindingMaxLength+contract.CryptoMaxValueEntries*(6*contract.CryptoMaxName+1024)) + 2048

// MaxMaterializationResultJSONBytes includes complete readable native layout.
const MaxMaterializationResultJSONBytes = 67 * materializationCompactResultLimit

func WriteMaterializationJSON(ctx context.Context, out io.Writer, result core.MaterializationResult) error {
	return writeMaterialization(ctx, out, result, false, nil)
}

func WriteMaterializationHuman(ctx context.Context, out io.Writer, result core.MaterializationResult) error {
	return writeMaterialization(ctx, out, result, true, nil)
}

func materializationResultIdentity(r core.MaterializationResult) (any, error) {
	if r.Validate() != nil {
		return nil, ErrMaterializationResult
	}
	if r.PreAdmission != nil {
		identity, ok := preAdmissionIdentity(contract.MaterializationOperation, r.OperationID, r.PreAdmission)
		if !ok {
			return nil, ErrMaterializationResult
		}
		return identity, nil
	}
	if r.RequestIdentity.IsZero() {
		return nil, ErrMaterializationResult
	}
	return readerID(r.RequestIdentity), nil
}

func writeMaterialization(ctx context.Context, out io.Writer, r core.MaterializationResult, human bool, sourceFailure *ConfigurationSourceFailure) error {
	if ctx == nil || out == nil {
		return ErrMaterializationResult
	}
	if !validConfigurationAdmissionSourceFailure(sourceFailure, r.PreAdmission, r.RequestIdentity, r.Result) {
		return ErrMaterializationResult
	}
	identity, err := materializationResultIdentity(r)
	if err != nil {
		return err
	}
	write := func(w *resultStreamWriter) {
		if human {
			materializationHuman(w, r, sourceFailure)
			return
		}
		q := queryBegin(w)
		q.field("schema", "ProductResult/v1")
		if sourceFailure != nil {
			q.field("source_failure", sourceFailure)
		}
		q.field("operation_kind", r.Operation)
		q.field("state_result", r.StateResult)
		q.field("effect_summary", "not-applicable")
		q.field("output_summary", "not-applicable")
		q.field("request_id", readerID(r.RequestID))
		q.field("operation_id", readerID(r.OperationID))
		q.field("request_identity", identity)
		q.field("replay_identity", "none")
		q.field("domain_id", readerID(r.DomainID))
		evidence := "unavailable"
		if r.Result.Evidence == core.AuthenticatedClosure {
			evidence = "canonical"
		}
		q.field("evidence_ceiling", evidence)
		q.object("result", func(o *queryObject) {
			o.field("outcome", r.Result.Outcome)
			o.field("reason", r.Result.Reason)
			o.field("evidence", r.Result.Evidence)
			o.field("observed_revision_id", readerID(r.Result.ObservedRevision))
			o.field("observed_snapshot_id", readerID(r.Result.ObservedSnapshotID))
		})
		materializationFailureField(q, "failure", r.Failure)
		q.array("effects", 0, nil)
		q.array("outputs", 0, nil)
		q.array("duties", 0, nil)
		q.array("hazards", 0, nil)
		q.array("warning_summary", 0, nil)
		q.field("capsule_policy", "none")
		if r.Payload == nil {
			q.field("operation_payload", "none")
			q.field("payload", nil)
		} else {
			q.field("operation_payload", contract.MaterializationPayloadSchema)
			q.object("payload", func(o *queryObject) { materializationPayload(o, *r.Payload) })
		}
		q.end()
		w.text("\n")
	}
	if !human {
		return writeReadableResultJSON(ctx, out, materializationCompactResultLimit, ErrMaterializationResult, write)
	}
	return writeResultStream(ctx, out, materializationCompactResultLimit, ErrMaterializationResult, write)
}

func materializationHuman(w *resultStreamWriter, r core.MaterializationResult, sourceFailure *ConfigurationSourceFailure) {
	if r.Payload != nil {
		w.text("Materialize file: ")
		w.value(r.Payload.Target.Path)
		w.text("\nFormat: " + r.Payload.Target.Format + "\n")
	}
	w.text("materialize: " + string(r.StateResult) + "\n")
	w.text(configurationSourceFailureHuman(sourceFailure))
	administrativeIdentityHuman(w, r.OperationID, r.PreAdmission)
	if r.Result.Outcome != core.ObservedCurrent || r.Result.Reason != core.NoReason {
		administrativeCoreHuman(w, "Result", r.Result)
	}
	if r.Failure != nil {
		w.text("Failure: " + string(r.Failure.Stage) + " / " + string(r.Failure.Reason) + ".\n")
	}
	if p := r.Payload; p != nil {
		f := p.Facts
		w.text("Replacement: " + string(f.Replacement) + "; installed verification=" + string(f.InstalledVerification) + "; completion=" + string(f.NativeCompletion) + ".\n")
		w.text("Recipient: " + readerID(p.Recipient.SubjectID) + ".\n")
		for _, entry := range p.Entries {
			w.text("Entry: ")
			w.value(entry.Name)
			w.text(fmt.Sprintf("; slot=%d.\n", entry.Slot))
		}
		w.text("Candidate verification: " + string(f.CandidateVerification) + ".\n")
		w.text("Plaintext disk disclosure: " + string(f.Disclosure) + ".\n")
		w.text("Candidate cleanup: " + string(f.Cleanup) + ".\n")
		if f.CleanupFailure != nil {
			w.text("Cleanup failure: " + string(f.CleanupFailure.Stage) + " / " + string(f.CleanupFailure.Reason) + ".\n")
		}
		if f.ResiduePath != "" {
			w.text("Private residue: ")
			w.value(f.ResiduePath)
			w.text(".\n")
		}
		if f.Cleanup == contract.MaterializationCandidateCleanupFailed || f.Cleanup == contract.MaterializationCandidateCleanupUnknown {
			w.text("No supported candidate cleanup action is established by this result.\n")
		}
	}
}

func materializationFailureField(o *queryObject, name string, failure *contract.MaterializationFailure) {
	if failure == nil {
		o.field(name, nil)
		return
	}
	o.object(name, func(f *queryObject) { f.field("stage", failure.Stage); f.field("reason", failure.Reason) })
}

func materializationPayload(o *queryObject, p contract.MaterializationPayload) {
	o.field("schema", p.Schema)
	o.id("request_identity", p.RequestIdentity)
	o.id("domain_id", p.DomainID)
	o.id("head_revision_id", p.HEADRevision)
	o.id("snapshot_id", p.SnapshotID)
	o.object("recipient", func(r *queryObject) {
		r.field("subject_kind", p.Recipient.SubjectKind)
		r.id("recipient_id", p.Recipient.SubjectID)
		r.object("binding", func(b *queryObject) {
			binding := p.Recipient.Binding
			b.id("binding_id", binding.BindingID)
			b.id("binding_incarnation_id", binding.BindingIncarnationID)
			b.field("binding_serial", binding.BindingSerial)
			b.field("provider", binding.Provider)
			b.field("wrap_profile", binding.WrapProfile)
			b.field("protection_class", binding.ProtectionClass)
			b.field("key_selector", binding.KeySelector)
			b.field("public_key_spki", binding.SPKI)
			b.id("fingerprint", binding.Fingerprint)
		})
	})
	o.object("target", func(t *queryObject) {
		t.field("path", p.Target.Path)
		t.id("surface_id", p.Target.SurfaceID)
		t.field("format", p.Target.Format)
		t.field("native_profile", p.Target.NativeProfile)
	})
	o.array("entries", len(p.Entries), func(at int) {
		entry := p.Entries[at]
		e := queryBegin(o.w)
		e.field("name", entry.Name)
		e.field("slot", entry.Slot)
		e.id("entry_incarnation_id", entry.EntryIncarnationID)
		e.id("value_state_id", entry.ValueStateID)
		e.field("value_source", entry.ValueSource)
		e.field("confidentiality_class", entry.ConfidentialityClass)
		e.end()
	})
	o.object("facts", func(f *queryObject) {
		facts := p.Facts
		f.field("replacement", facts.Replacement)
		f.field("candidate_verification", facts.CandidateVerification)
		f.field("installed_verification", facts.InstalledVerification)
		f.field("native_completion", facts.NativeCompletion)
		f.field("plaintext_disk_disclosure", facts.Disclosure)
		f.field("candidate_cleanup", facts.Cleanup)
		materializationFailureField(f, "failure", facts.Failure)
		materializationFailureField(f, "cleanup_failure", facts.CleanupFailure)
		if facts.ResiduePath != "" {
			f.field("residue_path", facts.ResiduePath)
		}
	})
}

func MaterializationExitCode(r core.MaterializationResult) int {
	if _, err := materializationResultIdentity(r); err != nil {
		return 2
	}
	if r.StateResult == contract.MaterializationSuccess {
		return 0
	}
	if r.StateResult == contract.MaterializationUnavailable {
		return 3
	}
	return 2
}
