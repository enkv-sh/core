package compositiongcp

import (
	"context"
	"encoding/json"
	core "enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/installedarchive"
	gcpprovider "enkv.sh/providers/gcp"
	"reflect"
	"testing"
)

func readerConfig(t *testing.T) (context.Context, ReaderConfig) {
	t.Helper()
	ctx, cell := localConfig(t)
	fixture, basisBytes := installedarchive.LoadReader(t, "gcp")
	var basisImage struct {
		Schema     int    `json:"schema"`
		Kind       string `json:"kind"`
		Descriptor []byte `json:"descriptor"`
	}
	if err := json.Unmarshal(basisBytes, &basisImage); err != nil || basisImage.Schema != 2 || basisImage.Kind != "genesis" {
		t.Fatal("independent public fixture basis", err)
	}
	cell.Store.Domain = fixture.Archive.Domain
	cell.Store.Endpoint = "https://storage." + fixture.Archive.Location.Region + ".rep.googleapis.com/storage/v1/"
	cell.Store.Region = fixture.Archive.Location.Region
	cell.Store.Bucket = fixture.Archive.Location.Bucket
	cell.Store.Prefix = fixture.Archive.Location.PrefixBeforeHEAD

	store, err := gcpprovider.NewStore(ctx, cell.Store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (core.PublicBasis{Descriptor: basisImage.Descriptor}).ControlCore(cell.Store.Domain, store.Descriptor()); err != nil {
		t.Fatal("independent complete basis refused", err)
	}
	validator := core.NewPublicConfigurationValidator(nil)
	return ctx, ReaderConfig{Candidate: gcpprovider.CandidateReadConfig{Client: cell.Store.Client, Region: cell.Store.Region, Bucket: cell.Store.Bucket, Prefix: cell.Store.Prefix, CredentialRoute: cell.Store.CredentialRoute}, ExpectedDomain: cell.Store.Domain, ExpectedStore: store.Descriptor(), PublicBasis: core.PublicBasis{Descriptor: basisImage.Descriptor}, Validator: validator}
}

// full_only: false
func TestNewReaderPinsGCPComponentsWithoutEffects(t *testing.T) {
	ctx, c := readerConfig(t)
	engine, err := NewReader(ctx, c)
	if err != nil || engine == nil {
		t.Fatal("fixed Reader did not construct", err)
	}
	engine.Close()
	engine.Close()
	// The shared selected adapter exposes only the public read surface.
	var selected core.PublicSelectedReader = &publicSelectedStore{}
	typ := reflect.TypeOf(selected)
	if typ.NumMethod() != 4 {
		t.Fatal("selected Reader gained a non-read method", typ.NumMethod())
	}
	if selected.Descriptor().Valid() || selected.Read(context.Background(), "HEAD", 1).Status != contract.ReadInvalid {
		t.Fatal("empty adapter reported usable public state")
	}
	selected.Close()
}

// full_only: false
func TestNewReaderRejectsUnfixedGCPInputs(t *testing.T) {
	for _, name := range []string{"domain", "Store", "basis", "mixed basis", "interpretation", "route", "location", "credentials"} {
		t.Run(name, func(t *testing.T) {
			ctx, c := readerConfig(t)
			switch name {
			case "domain":
				c.ExpectedDomain = contract.ID{}
			case "Store":
				c.ExpectedStore = contract.Descriptor{}
			case "basis":
				c.PublicBasis = core.PublicBasis{}
			case "mixed basis":
				c.PublicBasis.Control = []byte{1}
			case "interpretation":
				c.Validator = nil
			case "route":
				c.Candidate.CredentialRoute = ""
			case "location":
				c.Candidate.Region = ""
			case "credentials":
				c.Candidate.Client = nil
			}
			engine, err := NewReader(ctx, c)
			if engine != nil {
				engine.Close()
			}
			if err == nil || engine != nil {
				t.Fatal("unfixed Reader installed", err)
			}
		})
	}
}

// full_only: false
func TestNewReaderRejectsAbsentOrCanceledGCPContext(t *testing.T) {
	_, c := readerConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, input := range []context.Context{nil, ctx} {
		engine, err := NewReader(input, c)
		if engine != nil {
			engine.Close()
		}
		if err == nil || engine != nil {
			t.Fatal("inactive context installed Reader")
		}
	}
}
