package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"path/filepath"
	"time"

	"enkv.sh/compositions/configuration"
	"enkv.sh/core/testsupport/nativeprocess"
)

const sourcePairInspectorFlag = "--inspect-source-pair"

func runSourcePairInspector(args []string, out io.Writer) int {
	flags := flag.NewFlagSet("inspect-source-pair", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	source := flags.String("source", "", "")
	encoding := flags.String("source-format", "", "")
	if out == nil || flags.Parse(args) != nil || len(flags.Args()) != 0 || !filepath.IsAbs(*source) || filepath.Clean(*source) != *source || *encoding != "json" {
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pair, err := configuration.Capture(ctx, *source, configuration.JSON)
	if err != nil {
		return 2
	}
	defer pair.Close()
	model, parseErr := configuration.Parse(ctx, pair)
	if parseErr != nil || model == nil || !model.Resolved || pair.Generated == nil {
		if closeErr := pair.Close(); closeErr != nil {
			return 2
		}
		return 2
	}
	facts := nativeprocess.SourcePairFacts{Schema: "PublicSourcePairFacts/v1", GeneratedReference: model.Generated, Resolved: true,
		DomainID: model.DomainID, FileID: model.FileID, Format: uint8(pair.Format),
		EditableDigest: pair.Editable.Digest(), GeneratedDigest: pair.Generated.Digest(),
		EditableLength: uint64(pair.Editable.Size()), GeneratedLength: uint64(pair.Generated.Size()),
		Basis: nativeprocess.SourcePairBasis{Descriptor: bytes.Clone(model.Basis.Descriptor), Control: bytes.Clone(model.Basis.Control), Selection: bytes.Clone(model.Basis.Selection),
			SigningAnchor: bytes.Clone(model.Basis.SigningAnchor), StoreConfiguration: bytes.Clone(model.Basis.StoreConfiguration), HEAD: bytes.Clone(model.Basis.HEAD), Root: bytes.Clone(model.Basis.Root)}}
	for _, page := range model.Basis.RecipientPages {
		facts.Basis.RecipientPages = append(facts.Basis.RecipientPages, bytes.Clone(page))
	}
	for _, row := range model.Basis.Enrollment {
		facts.Basis.Enrollment = append(facts.Basis.Enrollment, nativeprocess.SourcePairEnrollment{ID: row.ID, Status: row.Status, DisplayName: row.DisplayName})
	}
	for _, row := range model.GeneratedRecipients {
		fact := nativeprocess.SourcePairRecipient{Reference: row.Reference, ID: row.ID,
			Encryption: nativeprocess.SourcePairKey{Selector: row.Encryption.Selector, PublicKey: bytes.Clone(row.Encryption.PublicKey), Binding: nativeprocess.SourcePairBinding{ID: row.Encryption.Binding.ID, Incarnation: row.Encryption.Binding.Incarnation, Serial: row.Encryption.Binding.Serial, Protection: row.Encryption.Binding.Protection}}}
		if row.Creation != nil {
			fact.Creation = &nativeprocess.SourcePairCreation{Snapshot: row.Creation.Snapshot, Nonce: row.Creation.Nonce}
		}
		facts.GeneratedRecipients = append(facts.GeneratedRecipients, fact)
	}
	unchangedErr := pair.CheckUnchanged(ctx)
	closeErr := pair.Close()
	if unchangedErr != nil || closeErr != nil || ctx.Err() != nil {
		return 2
	}
	body, err := json.Marshal(facts)
	if err != nil || len(body)+1 > nativeprocess.SourcePairFactsLimit {
		return 2
	}
	body = append(body, '\n')
	n, err := out.Write(body)
	if err != nil || n != len(body) {
		return 2
	}
	return 0
}

// Recapture compares source images. Parsed models also own private capture
// handles, so model equality cannot establish byte identity across captures.
type publicPairImage struct {
	format                        configuration.Format
	editable, generated           [32]byte
	editableBytes, generatedBytes int64
}

func capturedPublicPair(pair *configuration.Pair) publicPairImage {
	if pair == nil || pair.Editable == nil || pair.Generated == nil {
		return publicPairImage{}
	}
	return publicPairImage{format: pair.Format, editable: pair.Editable.Digest(), generated: pair.Generated.Digest(), editableBytes: pair.Editable.Size(), generatedBytes: pair.Generated.Size()}
}

func (image publicPairImage) matches(pair *configuration.Pair) bool {
	return image.format != 0 && image == capturedPublicPair(pair)
}
