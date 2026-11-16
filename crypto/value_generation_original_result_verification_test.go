package crypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"slices"
	"testing"

	"enkv.sh/core/contract"
	"enkv.sh/crypto/internal/custody"
)

func generatedVerificationFixture(t *testing.T, recovery bool) (generatedRuntimeFixture, []byte) {
	t.Helper()
	f, _, packet := generatedAdoptionFixture(t, recovery)
	e := f.adoption.Result.Expected
	x := e.Template
	template, err := contract.GeneratorTemplateID(x)
	if err != nil {
		t.Fatal("verification template", err)
	}
	a := contract.GeneratedAttemptRecord{LifecycleMode: contract.GeneratorLifecycleManaged, Schema: contract.GeneratedAttemptRecordSchema, DomainID: e.Plan.DomainID, OperationID: e.Plan.OperationID,
		LineageID: x.LineageID, AttemptID: x.AttemptID, TemplateDigest: template, PredecessorAttemptID: x.PredecessorAttemptID,
		OwnerID: x.DutyID, ResourceID: x.ResourceIncarnationID, TransmissionID: x.TransmissionID, ResultID: x.ResultID, InboxID: x.InboxID,
		DescriptorID: x.DescriptorID, ConfigContractID: x.ConfigContractID, ExecutorID: x.ExecutorID, CredentialRouteID: x.CredentialRouteID,
		ResourceContractID: x.ResourceContractID, ResultContractID: x.ResultContractID, RequestDigest: e.RequestDigest,
		State: contract.GeneratedEffectClosedWithResidue, Stage: contract.GeneratedStageTerminal, CompletionClass: x.CompletionClass,
		Facts: contract.EmptyGeneratorVector(contract.GeneratorVectorFacts), Progress: contract.EmptyGeneratorVector(contract.GeneratorVectorProgress),
		Support: contract.EmptyGeneratorVector(contract.GeneratorVectorSupport), History: contract.EmptyGeneratorVector(contract.GeneratorVectorHistory)}
	prior := f.compare
	f.compare = contract.CryptoGeneratedCompareRequest{Context: prior.Context, Purpose: 5, Original: a,
		PlanGraph: prior.PlanGraph, UsePlanDigest: prior.UsePlanDigest, MaterialID: prior.MaterialID,
		OriginalResult: f.adoption.Result.Reference, OriginalOwnerKind: 11, OriginalOwnerID: x.HazardID, Target: contract.EmptyGeneratorVector(contract.GeneratorVectorTargets)}
	f.compare.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(f.compare)
	if err != nil {
		t.Fatal("verification carrier", err)
	}
	f.verification = generatedOriginalVerificationAdmissionInput{
		Session: f.adoption.Session, Material: f.adoption.Material, SeedAccess: f.adoption.SeedAccess,
		Result: f.adoption.Result, Target: f.adoption.Target,
	}
	empty := contract.EmptyGeneratorVector
	hazard := contract.GeneratedHazardRecord{Schema: contract.GeneratedHazardRecordSchema, DomainID: a.DomainID, HazardID: x.HazardID,
		OriginalOperationID: a.OperationID, OriginalAttemptID: a.AttemptID, OwnerID: a.OwnerID,
		ResourceID: a.ResourceID, DescriptorID: a.DescriptorID, ConfigContractID: a.ConfigContractID, ExecutorID: a.ExecutorID,
		CredentialRouteID: a.CredentialRouteID, ResourceContractID: a.ResourceContractID, ResultContractID: a.ResultContractID,
		Exposure: contract.GeneratedExposurePossibleLive, CompletionClass: a.CompletionClass, Fenced: 1,
		CapacityReservation: empty(contract.GeneratorVectorSupport), OriginalResults: contract.EmptyGeneratorRecordSet(contract.GeneratorHazardResults),
		Target: empty(contract.GeneratorVectorTargets), History: a.History, Support: empty(contract.GeneratorVectorSupport), Consumers: empty(contract.GeneratorVectorConsumers)}
	hazardBody, err := contract.EncodeGeneratedHazardRecord(hazard)
	if err != nil {
		t.Fatal("verification owner body", err)
	}
	f.verification.Owner = contract.SupportRecord{Kind: contract.GeneratedHazardSupportKind, RecordID: x.HazardID, Body: hazardBody}
	fact, err := contract.InspectSupportRecordDigest(a.DomainID, f.verification.Owner)
	if err != nil {
		t.Fatal("verification owner fact", err)
	}
	attemptBody, err := contract.EncodeGeneratedAttemptRecord(a)
	if err != nil {
		t.Fatal("verification original body", err)
	}
	attemptFact, err := contract.InspectSupportRecordDigest(a.DomainID, contract.SupportRecord{
		Kind: contract.GeneratedAttemptSupportKind, RecordID: a.AttemptID, Body: attemptBody})
	if err != nil {
		t.Fatal("verification original fact", err)
	}
	f.verification.Session.Output.Rows.Facts = append(f.verification.Session.Output.Rows.Facts, attemptFact, fact)
	slices.SortFunc(f.verification.Session.Output.Rows.Facts, func(x, y contract.SupportRecordDigest) int {
		if x.Kind() != y.Kind() {
			return int(x.Kind()) - int(y.Kind())
		}
		xid, yid := x.RecordID(), y.RecordID()
		return bytes.Compare(xid[:], yid[:])
	})
	f.verification.Session.BeforePublic.RequiredSupport, err = contract.RequiredSupportDescriptorFromDigests(a.DomainID, f.verification.Session.Output.Rows.Facts)
	if err != nil {
		t.Fatal("verification selected support descriptor", err)
	}
	if err := f.verification.Session.Output.Inspect(f.verification.Session.BeforePublic); err != nil {
		t.Fatal("verification selected output witness", err)
	}
	f.declaration = nil
	return f, packet
}

// full_only: false
func TestGeneratedOriginalVerificationAuthenticatesWithoutParentOrAdoption(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprint(recovery), func(t *testing.T) {
			f, packet := generatedVerificationFixture(t, recovery)
			r := f.verificationRuntime(t)
			op, uses := generatedAdoptionCompare(t, r, f)
			if len(uses) != 1 || uses[0].Purpose != contract.KeyUseMaterialOpen || uses[0].Count != 1 {
				t.Fatal("verification did not open one current seed", uses)
			}
			body, err := contract.EncodeCryptoGeneratedVerifyRequest(contract.CryptoGeneratedVerifyRequest{OperationRef: op, Context: f.compare.Context,
				Result: packet, ExpectedResult: contract.GeneratorDescriptor{Digest: contract.Hash(packet), Length: uint64(len(packet)), Count: 1}})
			if err != nil {
				t.Fatal(err)
			}
			reply := applyCall(r, context.Background(), contract.CryptoPrepare, body)
			ref, err := contract.InspectGeneratorResultReference(reply.Body)
			if reply.ResultCode != contract.CryptoSuccess || err != nil || ref != f.compare.OriginalResult || len(reply.Body) != 70 || len(reply.KeyUseRows) != 0 {
				t.Fatal("verification did not return its exact bounded reference", reply.ResultCode, err)
			}
			if duplicate := applyCall(r, context.Background(), contract.CryptoPrepare, body); duplicate.ResultCode != contract.CryptoAlreadyUsed || len(duplicate.Body) != 0 {
				t.Fatal("original verification was reusable", duplicate.ResultCode)
			}
			r.retireGenerated()
			if r.generated != nil || r.slot != nil {
				t.Fatal("verification retained a custody owner")
			}
		})
	}
}

// full_only: false
func TestGeneratedOriginalVerificationRefusesUnauthenticatedPayloadLayers(t *testing.T) {
	for _, damage := range []string{"transfer", "package", "ciphertext", "semantic"} {
		t.Run(damage, func(t *testing.T) {
			f, packet := generatedVerificationFixture(t, true)
			result, err := contract.DecodeGeneratedResultRecord(packet)
			if err != nil {
				t.Fatal(err)
			}
			switch damage {
			case "transfer":
				result.Transfer.Ciphertext[0] ^= 1
			case "package":
				result.Payload.PackageCheck[0] ^= 1
			case "ciphertext":
				result.Payload.Ciphertext[0] ^= 1
			case "semantic":
				result.Payload.SemanticCommitment[0] ^= 1
			}
			packet, err = contract.EncodeGeneratedResultRecord(result)
			if err != nil {
				t.Fatal(err)
			}
			f.compare.OriginalResult.ResultBodyDigest = contract.Hash(packet)
			f.verification.Result.Reference = f.compare.OriginalResult
			f.compare.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(f.compare)
			if err != nil {
				t.Fatal(err)
			}
			r := f.verificationRuntime(t)
			op, _ := generatedAdoptionCompare(t, r, f)
			body, err := contract.EncodeCryptoGeneratedVerifyRequest(contract.CryptoGeneratedVerifyRequest{OperationRef: op, Context: f.compare.Context,
				Result: packet, ExpectedResult: contract.GeneratorDescriptor{Digest: contract.Hash(packet), Length: uint64(len(packet)), Count: 1}})
			if err != nil {
				t.Fatal(err)
			}
			reply := applyCall(r, context.Background(), contract.CryptoPrepare, body)
			if reply.ResultCode != contract.CryptoStoredAuthenticationFailed || len(reply.Body) != 0 {
				t.Fatal("verification admitted unauthenticated original bytes", damage, reply.ResultCode)
			}
			r.retireGenerated()
		})
	}
}

// full_only: false
func TestGeneratedOriginalVerificationCannotUseAdoptionOrProducer(t *testing.T) {
	for _, variant := range []uint8{3, 4, 5, 6} {
		t.Run(fmt.Sprint(variant), func(t *testing.T) {
			f, packet := generatedVerificationFixture(t, false)
			r := f.verificationRuntime(t)
			op, _ := generatedAdoptionCompare(t, r, f)
			body, err := contract.EncodeCryptoGeneratedAdoptRequest(contract.CryptoGeneratedAdoptRequest{OperationRef: op, Context: f.compare.Context,
				Result: packet, ExpectedResult: contract.GeneratorDescriptor{Digest: contract.Hash(packet), Length: uint64(len(packet)), Count: 1}})
			if err != nil {
				t.Fatal(err)
			}
			body[32+4+contract.CryptoApplyContextLength] = variant
			reply := applyCall(r, context.Background(), contract.CryptoPrepare, body)
			if reply.ResultCode == contract.CryptoSuccess || len(reply.Body) != 0 || len(reply.KeyUseRows) != 0 {
				t.Fatal("verification granted a different prepare right", variant)
			}
			r.retireGenerated()
		})
	}
}

// full_only: false
func TestGeneratedOriginalVerificationCannotFreezeOrClaim(t *testing.T) {
	for _, kind := range []contract.CryptoKind{contract.CryptoFreeze, contract.CryptoClaim} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			f, packet := generatedVerificationFixture(t, false)
			r := f.verificationRuntime(t)
			op, _ := generatedAdoptionCompare(t, r, f)
			beforePublicStateDescriptor, err := contract.PublicStateDescriptor(f.verification.Session.BeforePublic)
			if err != nil {
				t.Fatal(err)
			}
			access, err := contract.AccessRecordsDescriptor(f.compare.Context.DomainID, nil)
			if err != nil {
				t.Fatal(err)
			}
			support, err := contract.RequiredSupportDescriptor(f.compare.Context.DomainID, nil)
			if err != nil {
				t.Fatal(err)
			}
			results, err := contract.GeneratorResultReferencesDescriptor(nil)
			if err != nil {
				t.Fatal(err)
			}
			keyUses, err := contract.CryptoGeneratedKeyUseDescriptor(nil)
			if err != nil {
				t.Fatal(err)
			}
			frozen := contract.CryptoGeneratedFreezeRequest{OperationRef: op, Context: f.compare.Context,
				PhaseID: consumerID("verification cannot freeze phase"), RequestIdentityDigest: consumerID("verification cannot freeze request"),
				CandidatePublicStateDescriptor: beforePublicStateDescriptor, CandidateAccess: access, CandidateSupport: support,
				HeadCoreDigest: consumerID("verification cannot freeze head"), ConditionDigest: f.compare.Context.OriginalConditionDigest,
				ActualResults: results, KeyUses: keyUses}
			var body []byte
			if kind == contract.CryptoFreeze {
				body, err = contract.EncodeCryptoGeneratedFreezeRequest(frozen)
			} else {
				body, err = contract.EncodeCryptoGeneratedClaimRequest(contract.CryptoGeneratedClaimRequest(frozen))
			}
			if err != nil {
				t.Fatal(err)
			}
			reply := applyCall(r, context.Background(), kind, body)
			if reply.ResultCode != contract.CryptoAlreadyUsed || len(reply.Body) != 0 || len(reply.KeyUseRows) != 0 {
				t.Fatal("verification accepted or exposed facts for a forbidden terminal stage", kind, reply.ResultCode)
			}
			verify, err := contract.EncodeCryptoGeneratedVerifyRequest(contract.CryptoGeneratedVerifyRequest{OperationRef: op, Context: f.compare.Context,
				Result: packet, ExpectedResult: contract.GeneratorDescriptor{Digest: contract.Hash(packet), Length: uint64(len(packet)), Count: 1}})
			if err != nil {
				t.Fatal(err)
			}
			if reply := applyCall(r, context.Background(), contract.CryptoPrepare, verify); reply.ResultCode != contract.CryptoAlreadyUsed || len(reply.Body) != 0 || len(reply.KeyUseRows) != 0 {
				t.Fatal("forbidden terminal stage did not consume verification", kind, reply.ResultCode)
			}
			r.retireGenerated()
		})
	}
}

// full_only: false
func TestGeneratedOriginalVerificationRejectsChangedStageContextAndOriginal(t *testing.T) {
	for _, damage := range []string{"operation", "admission", "condition", "packet"} {
		t.Run(damage, func(t *testing.T) {
			f, packet := generatedVerificationFixture(t, false)
			r := f.verificationRuntime(t)
			op, _ := generatedAdoptionCompare(t, r, f)
			v := contract.CryptoGeneratedVerifyRequest{OperationRef: op, Context: f.compare.Context, Result: packet,
				ExpectedResult: contract.GeneratorDescriptor{Digest: contract.Hash(packet), Length: uint64(len(packet)), Count: 1}}
			switch damage {
			case "operation":
				v.OperationRef = consumerID("wrong operation")
			case "admission":
				v.Context.AdmissionID = consumerID("wrong admission")
			case "condition":
				v.Context.OriginalConditionDigest = consumerID("wrong condition")
			case "packet":
				result, err := contract.DecodeGeneratedResultRecord(packet)
				if err != nil {
					t.Fatal(err)
				}
				result.Transfer.Ciphertext[0] ^= 1
				v.Result, err = contract.EncodeGeneratedResultRecord(result)
				if err != nil {
					t.Fatal(err)
				}
				v.ExpectedResult.Digest = contract.Hash(v.Result)
			}
			body, err := contract.EncodeCryptoGeneratedVerifyRequest(v)
			if err != nil {
				t.Fatal(err)
			}
			reply := applyCall(r, context.Background(), contract.CryptoPrepare, body)
			if reply.ResultCode != contract.CryptoInvalidAdmission || len(reply.Body) != 0 {
				t.Fatal("changed verification context or original was accepted", reply.ResultCode)
			}
			r.retireGenerated()
		})
	}
}

// full_only: false
func TestGeneratedOriginalVerificationQualifiesExactSelectedOwnerAndAttempt(t *testing.T) {
	for _, mode := range []string{"owner kind", "owner ID", "owner body", "owner absent", "attempt body"} {
		t.Run(mode, func(t *testing.T) {
			f, _ := generatedVerificationFixture(t, false)
			switch mode {
			case "owner kind":
				f.compare.OriginalOwnerKind = contract.GeneratedDutySupportKind
			case "owner ID":
				f.compare.OriginalOwnerID = consumerID("different original owner")
			case "owner body":
				f.verification.Owner.Body = append([]byte(nil), f.verification.Owner.Body...)
				f.verification.Owner.Body[2] ^= 1
			case "owner absent":
				f.verification.Owner = contract.SupportRecord{}
			case "attempt body":
				f.compare.Original.History = contract.EmptyGeneratorVector(contract.GeneratorVectorSupport)
			}
			var err error
			f.compare.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(f.compare)
			if err != nil {
				t.Fatal("legal changed carrier fixture", err)
			}
			r := newConsumerRuntime(t, f.base.route)
			body, err := contract.EncodeCryptoGeneratedCompareRequest(f.compare)
			if err != nil {
				t.Fatal(err)
			}
			before := f.base.route.privateCalls
			if err := r.admitGeneratedVerification(f.compare, f.verification, body, f.base.deadline); err == nil || r.generated != nil || f.base.route.privateCalls != before {
				t.Fatal("unqualified selected owner or original attempt admitted", mode, err)
			}
		})
	}
}

// full_only: false
func TestGeneratedOriginalVerificationBindsSelectedMaterialAndGraph(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		for _, change := range []string{"seed package", "graph result uses"} {
			t.Run(fmt.Sprintf("recovery%t/%s", recovery, change), func(t *testing.T) {
				f, _ := generatedVerificationFixture(t, recovery)
				selected := f.verification.Session.BeforePublic.RequiredSupport
				seed := bytes.Repeat([]byte{71}, 32)
				defer clear(seed)
				var err error
				if change == "graph result uses" {
					graph, err := contract.DecodeGeneratorPlanBundle(f.verification.Session.Graph)
					if err != nil {
						t.Fatal(err)
					}
					index := slices.IndexFunc(graph.ResultUses, func(row contract.GeneratorResultUse) bool { return row.ResultID == f.compare.Original.ResultID })
					graph.ResultUses[index].MaxSecret--
					graph.UsePlan.ResultUses, err = contract.GeneratorResultUsesDescriptor(graph.ResultUses)
					if err != nil {
						t.Fatal(err)
					}
					f.verification.Session.Graph, err = contract.EncodeGeneratorPlanBundle(graph)
					if err != nil || contract.ValidateGeneratorEffectGraph(graph) != nil {
						t.Fatal("replacement graph is not valid", err)
					}
					f.compare.PlanGraph, err = contract.GeneratorPlanBundleDescriptor(graph)
					if err != nil {
						t.Fatal(err)
					}
					f.compare.UsePlanDigest, err = contract.GeneratorUsePlanDigest(graph.UsePlan)
					if err != nil {
						t.Fatal(err)
					}
					f.verification.Material.Core.UsePlanDigest = f.compare.UsePlanDigest
					f.verification.Result.Expected.Plan = graph.UsePlan
					f.verification.Result.Expected.Use = graph.ResultUses[index]
				}
				f.verification.Material.SeedCheck, err = custody.SeedCheck(f.verification.Material.Core, seed)
				if err != nil {
					t.Fatal(err)
				}
				access, err := contract.DecodeAccessRecord(f.verification.SeedAccess)
				if err != nil {
					t.Fatal(err)
				}
				access.MaterialContextDigest, err = contract.OperationMaterialContextDigest(f.verification.Material.Core)
				if err != nil {
					t.Fatal(err)
				}
				access.PackageCheck = f.verification.Material.SeedCheck
				for i := range access.Wraps {
					wrap := &access.Wraps[i]
					index := slices.IndexFunc(f.base.q.Bindings, func(row contract.BindingTableRow) bool {
						return row.SubjectKind == wrap.SubjectKind && row.SubjectID == wrap.SubjectID
					})
					if index < 0 {
						t.Fatal("seed wrap has no current binding")
					}
					binding := f.base.q.Bindings[index]
					core, err := custody.SeedWrapCore(f.verification.Material.Core, binding)
					if err != nil {
						t.Fatal(err)
					}
					context, err := contract.RSAPacketContextDigest(core)
					if err != nil {
						t.Fatal(err)
					}
					packet, err := custody.EncodePacket(core.PacketKind, context, seed)
					if err != nil {
						t.Fatal(err)
					}
					wrap.RSACiphertext, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, &f.base.keys[wrap.SubjectID].PublicKey, packet, nil)
					clear(packet)
					if err != nil {
						t.Fatal(err)
					}
				}
				f.verification.SeedAccess, err = contract.EncodeAccessRecord(access)
				if err != nil || f.verification.Result.Expected.Validate(f.verification.Material) != nil {
					t.Fatal("replacement seed package is not self-consistent", err)
				}
				f.compare.Context.IntentDescriptor, err = contract.CryptoGeneratedAdmissionDescriptor(f.compare)
				if err != nil {
					t.Fatal(err)
				}
				if f.verification.Session.BeforePublic.RequiredSupport != selected || f.verification.Session.Output.Inspect(f.verification.Session.BeforePublic) != nil {
					t.Fatal("replacement changed the independent selected witness")
				}
				r := newConsumerRuntime(t, f.base.route)
				before := f.base.route.privateCalls
				if err := r.admitGeneratedOriginalVerification(f.compare, f.verification, f.base.deadline); err == nil || r.generated != nil || r.slot != nil || f.base.route.privateCalls != before {
					r.retireGenerated()
					t.Fatal("substituted original material admitted before private open", err)
				}
			})
		}
	}
}
