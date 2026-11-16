package nativeprocess

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// AddGeneratedLedgerOverlay observes the real installed producer custody. It
// replaces no provider, admission, normalizer, credential route or result.
func AddGeneratedLedgerOverlay(root string, overlay Overlay) (Overlay, error) {
	var mapping struct{ Replace map[string]string }
	var sources []Source
	body, err := os.ReadFile(overlay.Path)
	if err != nil || json.Unmarshal(body, &mapping) != nil {
		return Overlay{}, errors.New("generated observer overlay refused")
	}
	body, err = os.ReadFile(overlay.Manifest)
	if err != nil || json.Unmarshal(body, &sources) != nil {
		return Overlay{}, errors.New("generated observer manifest refused")
	}
	directory := filepath.Dir(overlay.Path)
	save := func(relative string, original, replacement []byte) error {
		target := filepath.Join(root, filepath.FromSlash(relative))
		if previous, exists := mapping.Replace[target]; exists {
			if relative != "compositions/full/generated_installation.go" {
				return errors.New("generated observer target already replaced")
			}
			found := false
			for index := range sources {
				if sources[index].Target == target && sources[index].Replacement == previous && sources[index].OriginalSHA256 == digest(original) {
					if found {
						return errors.New("generated observer duplicate source")
					}
					found = true
					if err := os.WriteFile(previous, replacement, 0600); err != nil {
						return err
					}
					sources[index].ReplacementSHA256 = digest(replacement)
				}
			}
			if !found {
				return errors.New("generated observer original source differs")
			}
			return nil
		}
		if len(original) == 0 {
			if _, err := os.Lstat(target); !os.IsNotExist(err) {
				return errors.New("generated observer virtual target exists")
			}
		}
		path := filepath.Join(directory, strings.ReplaceAll(relative, "/", "_"))
		if err := os.WriteFile(path, replacement, 0600); err != nil {
			return err
		}
		mapping.Replace[target] = path
		sources = append(sources, Source{Target: target, OriginalSHA256: digest(original), Replacement: path, ReplacementSHA256: digest(replacement)})
		return nil
	}
	const relative = "compositions/full/generated_installation.go"
	original, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
	if err != nil {
		return Overlay{}, err
	}
	effective := original
	if previous := mapping.Replace[filepath.Join(root, filepath.FromSlash(relative))]; previous != "" {
		effective, err = os.ReadFile(previous)
		if err != nil {
			return Overlay{}, err
		}
	}
	const anchor = "producer := configurationGeneratedProducerCustody(owner, fork)"
	if strings.Count(string(effective), anchor) != 1 {
		return Overlay{}, errors.New("generated custody observer anchor differs")
	}
	replacement := strings.Replace(string(effective), anchor, "producer := nativeProcessGeneratedProducerCustody(owner, fork, input, row)", 1)
	if err := save(relative, original, []byte(replacement)); err != nil {
		return Overlay{}, err
	}
	// Reuse the maintained ledger and synced JSON implementation. Effective
	// package-renamed bytes, including every update, enter the source manifest.
	for _, name := range []string{"io.go", "generator_ledger.go"} {
		source, err := os.ReadFile(filepath.Join(root, "tests", "shared", "records", name))
		if err != nil {
			return Overlay{}, err
		}
		target := "compositions/full/nativeprocess_generated_" + name
		if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(target))); !os.IsNotExist(err) {
			return Overlay{}, errors.New("generated observer virtual target exists")
		}
		if err := save(target, nil, []byte(strings.Replace(string(source), "package records", "package compositionfull", 1))); err != nil {
			return Overlay{}, err
		}
	}
	if err := save("compositions/full/nativeprocess_generated_custody.go", nil, []byte(generatedCustodyObserverSource)); err != nil {
		return Overlay{}, err
	}
	encoded, err := json.Marshal(mapping)
	if err != nil {
		return Overlay{}, err
	}
	manifest, err := json.Marshal(sources)
	if err != nil {
		return Overlay{}, err
	}
	if err = os.WriteFile(overlay.Path, encoded, 0600); err != nil {
		return Overlay{}, err
	}
	if err = os.WriteFile(overlay.Manifest, manifest, 0600); err != nil {
		return Overlay{}, err
	}
	overlay.SHA256, overlay.ManifestSHA256 = digest(encoded), digest(manifest)
	return overlay, nil
}

const generatedCustodyObserverSource = `package compositionfull
import (
 "bytes"
 "context"
 "encoding/json"
 "fmt"
 "sync"
 "enkv.sh/core"
 "enkv.sh/core/contract"
 enkvcrypto "enkv.sh/crypto"
)
var nativeGeneratedAllowance struct { sync.Mutex; creates,retires uint64 }
func nativeProcessGeneratedProducerCustody(owner *enkvcrypto.GeneratedCustody, fork *enkvcrypto.Runtime, input contract.GeneratedProducerInput, row contract.GeneratorImplementation) *core.InstalledGeneratedProducerCustody {
 out := configurationGeneratedProducerCustody(owner,fork)
 invoke := out.InvokeProducer
 out.InvokeProducer = func(ctx context.Context, locator, authority contract.ID) contract.GeneratedProducerResult {
  p,err := nativeProcessLoad()
  if err != nil { return contract.GeneratedProducerResult{Code:contract.CryptoInvalidAdmission} }
  x,e := input.Preparation,input.Expected
  intent,intentErr := contract.InspectGeneratorIntent(input.Intent)
  intentDigest,digestErr := contract.GeneratorIntentDigest(input.Intent)
  requestDigest,requestErr := configurationGeneratedRequestDigest(ctx,row,x.Action,input.Intent,input.Target)
  // The private Cloudflare ledger uses the plugin's public account and token
  // bytes. Their interpretation stays in this fixture, outside production.
  var settings struct { Account string ` + "`json:\"account\"`" + ` }
  settingsErr := json.Unmarshal(intent.Settings,&settings)
  event := nativeProcessEvent{Kind:"generator-refused",GeneratorAttempt:fmt.Sprintf("%x",x.AttemptID),GeneratorAccount:settings.Account,GeneratorAction:x.Action}
  var original contract.GeneratorSafeFacts
  if x.Action == contract.GeneratorActionDelete {
   facts,factsErr := contract.InspectGeneratorSafeFacts(input.OriginalFacts)
   if factsErr == nil { original = facts.GeneratorSafeFacts; event.GeneratorTarget = string(original.ResourceData) }
  }
  refuse := func() contract.GeneratedProducerResult { _ = nativeProcessRecord(event); return contract.GeneratedProducerResult{Code:contract.CryptoInvalidAdmission} }
  if !filepathGeneratedPolicy(p) || ctx == nil || ctx.Err() != nil || e.Validate(input.Custody.Material) != nil ||
   intentErr != nil || digestErr != nil || requestErr != nil || settingsErr != nil || settings.Account != p.GeneratorAccount ||
   x.DomainID != e.Plan.DomainID || x.OperationID != e.Plan.OperationID || x.PlanGraphID != e.Plan.PlanGraphID ||
   x.LineageID != e.Template.LineageID || x.AttemptID != e.Template.AttemptID || x.TransmissionID != e.Template.TransmissionID ||
   x.ResultID != e.Template.ResultID || x.ResultContractID != e.Template.ResultContractID || x.Action != e.Template.Action ||
   x.DescriptorID != e.Template.DescriptorID || x.ExecutorID != e.Template.ExecutorID || x.CredentialRouteID != e.Template.CredentialRouteID ||
   row.DescriptorID != x.DescriptorID || row.ExecutorID != x.ExecutorID || row.CredentialRouteID != x.CredentialRouteID ||
   x.RequestDigest != e.RequestDigest || x.RequestDigest != requestDigest || x.IntentDigest != e.Template.IntentDigest || x.IntentDigest != intentDigest ||
   x.LifecycleMode != contract.GeneratorLifecycleManaged || x.LifecycleMode != e.Template.LifecycleMode || x.LifecycleMode != intent.LifecycleMode ||
   intent.ConfigContractID != e.Template.ConfigContractID || x.ResourceContractID != e.Template.ResourceContractID || x.ResourceContractID != intent.ResourceContractID ||
   x.ResourceDigest != e.TargetResourceDigest { return refuse() }
  if x.Action == contract.GeneratorActionCreate {
   if len(input.OriginalFacts) != 0 { return refuse() }
  } else {
   resourceDigest,resourceErr := contract.GeneratorResourceDigest(original)
   if resourceErr != nil || resourceDigest != x.ResourceDigest || original.Action != contract.GeneratorActionCreate ||
    original.IntentDigest != x.IntentDigest || original.ResourceContractID != x.ResourceContractID ||
    (original.Disposition != contract.GeneratorDispositionCompleteCreate && original.Disposition != contract.GeneratorDispositionOwnedUnusableCreate) ||
    !bytes.Equal(original.Target,[]byte(p.GeneratorAccount)) || !generatorID.MatchString(event.GeneratorTarget) { return refuse() }
  }
  nativeGeneratedAllowance.Lock()
  allowed := false
  switch x.Action {
  case contract.GeneratorActionCreate: if nativeGeneratedAllowance.creates < p.GeneratorCreates { nativeGeneratedAllowance.creates++; allowed = true }
  case contract.GeneratorActionDelete: if nativeGeneratedAllowance.retires < p.GeneratorRetires { nativeGeneratedAllowance.retires++; allowed = true }
  }
  nativeGeneratedAllowance.Unlock()
  if !allowed { return refuse() }
  update := func(change func(*GeneratorFixtureLedger) error) error { return UpdateGeneratorFixtureLedger(p.GeneratorLedgerPath,p.GeneratorRunID,p.GeneratorAccount,change) }
  if err := update(func(ledger *GeneratorFixtureLedger) error {
   if x.Action == contract.GeneratorActionCreate { return ledger.BeginCreate(event.GeneratorAttempt) }
   // An unclosed prior delete is remote uncertainty, even after local join.
   for _, r := range ledger.Resources { if r.ID == event.GeneratorTarget && len(r.DeleteAttempts) != 0 { return nativeProcessRefused } }
   return ledger.BeginDelete(event.GeneratorAttempt,event.GeneratorTarget)
  }); err != nil { return refuse() }
  event.Kind = "generator-entry"
  if nativeProcessRecord(event) != nil { return contract.GeneratedProducerResult{Code:contract.CryptoInvalidAdmission} }
  returned := invoke(ctx,locator,authority)
  facts,code := returned.Facts,returned.Code
  _,factsErr := contract.ExpectedGeneratedResultCore(e,input.Custody.Material,facts)
  observation := &nativeProcessGeneratorReturn{Code:uint16(code),ExpectedResultValid:factsErr == nil}
  if _,err := contract.GeneratorSafeFactsLength(facts); err == nil {
   observation.CommonFacts = &nativeProcessGeneratorCommonFacts{Disposition:facts.Disposition,Reason:facts.Reason}
  }
  target := string(facts.ResourceData)
  resourcePresent := bytes.Equal(facts.Target,[]byte(p.GeneratorAccount)) && generatorID.MatchString(target)
  dispositionAccepted := facts.Disposition == contract.GeneratorDispositionCompleteCreate || facts.Disposition == contract.GeneratorDispositionOwnedUnusableCreate
  if x.Action != contract.GeneratorActionCreate {
   dispositionAccepted = bytes.Equal(facts.Target,original.Target) && bytes.Equal(facts.ResourceData,original.ResourceData) && facts.Disposition == contract.GeneratorDispositionRetirementAcknowledged
  }
  switch {
  case code != contract.CryptoSuccess: observation.Qualification = "producer-failed"
  case factsErr != nil: observation.Qualification = "facts-refused"
  case !resourcePresent: observation.Qualification = "resource-unavailable"
  case !dispositionAccepted: observation.Qualification = "disposition-refused"
  default:
   err = update(func(ledger *GeneratorFixtureLedger) error {
    if x.Action == contract.GeneratorActionCreate { return ledger.RecordCreate(event.GeneratorAttempt,target) }
    return ledger.RecordDelete(event.GeneratorAttempt,event.GeneratorTarget)
   })
   observation.Qualification = "qualified"
   if err != nil { observation.Qualification = "ledger-unavailable" }
  }
  if x.Action == contract.GeneratorActionCreate && resourcePresent { event.GeneratorTarget = target }
  event.Kind,event.GeneratorQualified,event.GeneratorReturn = "generator-return",observation.Qualification == "qualified",observation
  _ = nativeProcessRecord(event)
  // The harness checks the event separately. Never replace a real Product
  // result with a ledger error or fabricate provider uncertainty from it.
  return returned
 }
 return out
}
func filepathGeneratedPolicy(p nativeProcessPolicy) bool {
 return p.GeneratorLedgerPath != "" && ValidRunID(p.GeneratorRunID) && generatorID.MatchString(p.GeneratorAccount) && p.GeneratorCreates <= 3 && p.GeneratorRetires <= 8
}
`
