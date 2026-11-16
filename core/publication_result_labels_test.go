package core

import (
	"bytes"
	"slices"
	"testing"
	"unsafe"

	"enkv.sh/core/contract"
)

// full_only: false
func TestPublicationDescriptionsOwnTheAdmittedSelection(t *testing.T) {
	name, destination, service, canonical := []byte("captured-name"), []byte("destination"), []byte("service"), []byte("account/current")
	borrow := func(body []byte) string { return unsafe.String(unsafe.SliceData(body), len(body)) }
	domain, incarnation := contract.ID{1}, contract.ID{2}
	coordinate, err := contract.PublicationCoordinateID(domain, string(service), string(canonical))
	if err != nil {
		t.Fatal(err)
	}
	selected := &contract.ConsumerSelection{DomainID: domain, Entry: contract.ValueEntry{Name: borrow(name), Incarnation: incarnation}}
	current := publicationTargetPlan{coordinate: coordinate, destination: borrow(destination), selection: selected,
		valueBasis: contract.PublicationValueBasis{EntryIncarnationID: incarnation},
		target:     contract.OutputTarget{EntryIncarnationID: incarnation, ServiceContractID: borrow(service), CanonicalTarget: borrow(canonical)}}
	retainedCoordinate, _ := contract.PublicationCoordinateID(domain, "service", "account/retained")
	retained := publicationTargetPlan{coordinate: retainedCoordinate, deletion: true, selection: selected,
		target:   contract.OutputTarget{ServiceContractID: "service", CanonicalTarget: "account/retained"},
		retained: contract.PublicationCoordinate{DeletionDestinationID: "old-destination"}}
	plan := publicationPlan{targets: []publicationTargetPlan{current, retained}, vector: contract.PublicationOutcomeVector{DomainID: domain}}
	slices.SortFunc(plan.targets, func(a, b publicationTargetPlan) int { return bytes.Compare(a.coordinate[:], b.coordinate[:]) })
	for _, target := range plan.targets {
		plan.vector.Entries = append(plan.vector.Entries, contract.PublicationTargetOutcome{CoordinateID: target.coordinate})
	}
	descriptions, err := plan.captureDescriptions()
	if err != nil || len(descriptions) != 2 || cap(descriptions) != 2 {
		t.Fatal("admitted descriptions were not captured", err)
	}
	for _, body := range [][]byte{name, destination, service, canonical} {
		clear(body)
	}
	selected.Entry.Name = "new-name-at-the-same-slot"
	selected.Entry.Incarnation = contract.ID{3}
	for _, row := range descriptions {
		switch row.CoordinateID {
		case coordinate:
			if row.Origin != PublicationTargetCurrent || row.EntryName == nil || *row.EntryName != "captured-name" || row.DestinationID == nil || *row.DestinationID != "destination" || row.ServiceContractID != "service" || row.CanonicalTarget != "account/current" {
				t.Fatal("source mutation changed detached target labels", row)
			}
		case retainedCoordinate:
			if row.Origin != PublicationTargetRetainedDeletion || row.EntryName != nil || row.DestinationID == nil || *row.DestinationID != "old-destination" {
				t.Fatal("retained target borrowed a current or reused name", row)
			}
		default:
			t.Fatal("unexpected description coordinate")
		}
	}
	if unsafe.Sizeof(PublicationTargetDescription{}) != 88 || 24+1024*88+2*1024*16+1024*(256+256+256+1024) != 1957912 {
		t.Fatal("owned description account changed")
	}
}

// full_only: false
func TestPublicationDescriptionsRejectAnotherIncarnation(t *testing.T) {
	domain, incarnation := contract.ID{1}, contract.ID{2}
	coordinate, _ := contract.PublicationCoordinateID(domain, "service", "account/target")
	for _, condition := range []string{"missing-consumer", "domain", "selected-incarnation", "value-basis"} {
		t.Run(condition, func(t *testing.T) {
			target := publicationTargetPlan{coordinate: coordinate, destination: "output", target: contract.OutputTarget{EntryIncarnationID: incarnation, ServiceContractID: "service", CanonicalTarget: "account/target"},
				selection: &contract.ConsumerSelection{DomainID: domain, Entry: contract.ValueEntry{Name: "reused-name", Incarnation: incarnation}}, valueBasis: contract.PublicationValueBasis{EntryIncarnationID: incarnation}}
			switch condition {
			case "missing-consumer":
				target.selection = nil
			case "domain":
				target.selection.DomainID = contract.ID{3}
			case "selected-incarnation":
				target.selection.Entry.Incarnation = contract.ID{3}
			case "value-basis":
				target.valueBasis.EntryIncarnationID = contract.ID{3}
			}
			plan := publicationPlan{targets: []publicationTargetPlan{target}, vector: contract.PublicationOutcomeVector{DomainID: domain, Entries: []contract.PublicationTargetOutcome{{CoordinateID: coordinate}}}}
			if descriptions, err := plan.captureDescriptions(); err == nil || descriptions != nil {
				t.Fatal("different admitted selection supplied a current label")
			}
		})
	}
}
