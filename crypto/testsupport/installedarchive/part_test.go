package installedarchive

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"enkv.sh/core/contract"

	"testing"

	"enkv.sh/core/format"
)

// full_only: false
func TestSelectedProjectionRejectsOmissionDuplicateAndOldState(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			a := Load(t, family)
			headBody := a.MustObject(t, a.Location.PrefixBeforeHEAD+"/HEAD").Body
			head, err := format.DecodeHead(headBody)
			if err != nil {
				t.Fatal(err)
			}
			var prior format.Root
			var priorRef format.Ref
			found := false
			for _, object := range a.Objects {
				root, err := format.DecodeRoot(object.Body)
				if err != nil || root.Snapshot == head.Core.Root.Object {
					continue
				}
				priorRef, err = format.Reference(format.RootKind, a.Domain, root.Snapshot, 0, object.Body)
				if err != nil {
					t.Fatal(err)
				}
				prior = root
				found = true
				break
			}
			if !found || prior.AdministrativeIndex == head.Core.Root {
				t.Fatal("fixed archive lacks an old signed state")
			}
			oldRoot := a.MustObject(t, mustPartKey(t, a, priorRef))
			oldIndex := a.MustObject(t, mustPartKey(t, a, prior.AdministrativeIndex))
			parts, err := a.SelectedParts()
			if err != nil || len(parts) != 10 {
				t.Fatal("fixed selected projection fixture", len(parts), err)
			}
			matches, err := selectedProjectionEqual(a, parts)
			if err != nil || !matches {
				t.Fatal("exact selected fixture refused", err)
			}
			checkRefusal := func(label string, candidate []Part) {
				t.Helper()
				matches, err := selectedProjectionEqual(a, candidate)
				if err != nil || matches {
					t.Fatal(label, "accepted as complete selected projection", matches, err)
				}
			}
			checkRefusal("omitted selected part", append([]Part(nil), parts[:len(parts)-1]...))
			duplicate := append([]Part(nil), parts...)
			duplicate[len(duplicate)-1] = duplicate[0]
			checkRefusal("duplicate replacing selected part", duplicate)
			wrongRoot := append([]Part(nil), parts...)
			wrongRoot[2] = Part{Kind: "root", Ref: priorRef, Body: oldRoot.Body}
			checkRefusal("old archived root", wrongRoot)
			wrongIndex := append([]Part(nil), parts...)
			index := -1
			for i := range wrongIndex {
				if wrongIndex[i].Kind == "index page" {
					index = i
					break
				}
			}
			if index < 0 {
				t.Fatal("fixed selected projection lacks index")
			}
			wrongIndex[index] = Part{Kind: "index page",
				Ref: prior.AdministrativeIndex, Body: oldIndex.Body}
			checkRefusal("old archived index", wrongIndex)
		})
	}
}

func mustPartKey(t *testing.T, a Archive, ref format.Ref) string {
	t.Helper()
	key, err := format.Key(a.Location.PrefixBeforeHEAD, ref)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// full_only: false
func TestInstalledArchiveCurrentPublicSelection(t *testing.T) {
	for _, family := range []string{"aws", "gcp"} {
		t.Run(family, func(t *testing.T) {
			a := Load(t, family)
			h, err := format.DecodeHead(a.MustObject(t, a.Location.PrefixBeforeHEAD+"/HEAD").Body)
			if err != nil {
				t.Fatal("HEAD", err)
			}
			obj, err := a.selectedObject(h.Core.Root)
			if err != nil {
				t.Fatal(err)
			}
			root, err := format.DecodeRoot(obj.Body)
			if err != nil {
				t.Fatal("Root", err)
			}
			canonical, err := format.EncodeRoot(root)
			if err != nil || !bytes.Equal(canonical, obj.Body) {
				t.Fatal("Root canonical", err)
			}
			if root.OutputConfiguration.Schema != contract.OutputConfigurationSchema || root.SecretCount != 1 {
				t.Fatal("archive lost current configuration or secret")
			}
			var selectedAuthority *contract.RecipientRecord
			for _, ref := range root.Recipients {
				if ref == nil {
					continue
				}
				object, err := a.selectedObject(*ref)
				if err != nil {
					t.Fatal(err)
				}
				page, err := format.DecodeRecipientPage(object.Body)
				if err != nil {
					t.Fatal(err)
				}
				for _, row := range page.Slots {
					if row != nil && row.RecipientID == root.CurrentAccess.Core.AuthorityRecipientID {
						selectedAuthority = row
					}
				}
			}
			if selectedAuthority == nil || selectedAuthority.CurrentBinding == nil || selectedAuthority.CurrentBinding.KeySelector != a.AuthorityBinding.KeySelector {
				t.Fatal("archive authority binding differs from selected recipient")
			}
			req, err := contract.NewLifecycleRequest(h.Subject)
			if err != nil {
				t.Fatal(err)
			}
			key, err := x509.ParsePKIXPublicKey(a.SignerPublicKey)
			if err != nil {
				t.Fatal(err)
			}
			digest := req.Digest()
			public, ok := key.(*ecdsa.PublicKey)
			if !ok || !ecdsa.VerifyASN1(public, digest[:], h.AuthorizationSignature) {
				t.Fatal("archive HEAD signature differs")
			}

			if _, err := a.SelectedParts(); err != nil {
				t.Fatal("complete selected parts", err)
			}
		})
	}
}

func selectedProjectionEqual(a Archive, observed []Part) (bool, error) {
	expected, err := a.SelectedParts()
	if err != nil {
		return false, err
	}
	if len(expected) != len(observed) {
		return false, nil
	}
	for i, x := range expected {
		y := observed[i]
		if x.Kind != y.Kind || x.Ref != y.Ref || x.PhysicalOrdinal != y.PhysicalOrdinal || x.SupportKind != y.SupportKind || x.RecordID != y.RecordID || !bytes.Equal(x.Body, y.Body) {
			return false, nil
		}
	}
	return true, nil
}
