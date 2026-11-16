package compositionfull

import (
	"context"
	"errors"
	"io"
	"math"

	"enkv.sh/core"
)

const (
	MaxApplyPublicationApplyBytes = generatedResultOutputLimit
	applyPublicationCompactLimit  = MaxApplyPublicationApplyBytes + publicationCompactResultLimit + 256
	MaxApplyPublicationJSONBytes  = 67 * applyPublicationCompactLimit
	MaxApplyPublicationHumanBytes = applyPublicationCompactLimit
)

var ErrApplyPublicationResult = errors.New("apply publication result rendering refused")

func validApplyPublicationStage(stage core.ApplyPublicationStage) bool {
	switch stage.Stage {
	case "evaluated":
		return stage.Reason == "" && stage.Result != nil
	case "unstarted":
		if stage.Result != nil {
			return false
		}
		switch stage.Reason {
		case "apply-incomplete", "selection-unavailable", "selection-conflict", "deadline-expired":
			return true
		}
	}
	return false
}

func applyPublicationResultSize(apply, publication, framing, maximum uint64) (uint64, error) {
	if apply > MaxApplyPublicationApplyBytes || publication > publicationCompactResultLimit+256 || apply > math.MaxUint64-publication || apply+publication > math.MaxUint64-framing || apply+publication+framing > maximum {
		return 0, ErrApplyPublicationResult
	}
	return apply + publication + framing, nil
}

func applyPublicationStageSize(stage core.ApplyPublicationStage, body uint64, human bool) (uint64, error) {
	if !validApplyPublicationStage(stage) {
		return 0, ErrApplyPublicationResult
	}
	var framing uint64
	if stage.Stage == "evaluated" {
		framing = uint64(len(`{"stage":"evaluated","reason":null,"result":}`))
		if human {
			framing = uint64(len("publication:\nstage: evaluated\nreason: null\nresult:\n"))
		}
	} else {
		if body != 0 {
			return 0, ErrApplyPublicationResult
		}
		framing = uint64(len(`{"stage":"unstarted","reason":"` + stage.Reason + `","result":null}`))
		if human {
			framing = uint64(len("publication:\nstage: unstarted\nreason: " + stage.Reason + "\nresult: null\n"))
		}
	}
	if body > math.MaxUint64-framing || body > publicationCompactResultLimit {
		return 0, ErrApplyPublicationResult
	}
	return body + framing, nil
}

func WriteApplyPublicationJSON(out io.Writer, result core.PublicApplyPublicationResult) error {
	return writeApplyPublicationResult(out, result, false, nil)
}

func WriteApplyPublicationHuman(out io.Writer, result core.PublicApplyPublicationResult) error {
	return writeApplyPublicationResult(out, result, true, nil)
}

func writeApplyPublicationResult(out io.Writer, result core.PublicApplyPublicationResult, human bool, sourceFailure *ConfigurationSourceFailure, locations ...*resultStoreLocation) error {
	if out == nil || !validApplyPublicationStage(result.Publication) {
		return ErrApplyPublicationResult
	}
	var location *resultStoreLocation
	if len(locations) != 0 {
		location = locations[0]
	}
	renderApply, renderPublication := RenderApplyJSON, RenderPublicationJSON
	if human {
		renderApply, renderPublication = RenderApplyHuman, RenderPublicationHuman
	}
	var apply []byte
	var err error
	if sourceFailure != nil || location != nil {
		r := ConfigurationApplyResult{PublicApplyResult: result.Apply, SourceFailure: sourceFailure, storeLocation: location}
		if human {
			apply, err = r.RenderHuman()
		} else {
			apply, err = r.RenderJSON()
		}
	} else {
		apply, err = renderApply(result.Apply)
	}
	if err != nil {
		return err
	}
	var publication []byte
	if result.Publication.Result != nil {
		publication, err = renderPublication(*result.Publication.Result)
		if err != nil {
			return err
		}
	}
	var publicationSize uint64
	if human {
		publicationSize, err = applyPublicationStageSize(result.Publication, uint64(len(publication)), true)
		if err != nil {
			return err
		}
	}
	// Both complete stage bodies validate before delivery. They are written
	// directly; a second full concatenated response is never allocated.
	if human {
		if _, err := applyPublicationResultSize(uint64(len(apply)), publicationSize, 8, MaxApplyPublicationHumanBytes); err != nil {
			return err
		}
		if err := writeApplyPublicationText(out, "apply:\n"); err != nil {
			return err
		}
		if err := writeApplyPublicationBytes(out, apply); err != nil {
			return err
		}
		if len(apply) == 0 || apply[len(apply)-1] != '\n' {
			if err := writeApplyPublicationText(out, "\n"); err != nil {
				return err
			}
		}
		if result.Publication.Stage == "unstarted" {
			return writeApplyPublicationText(out, "publication:\nstage: unstarted\nreason: "+result.Publication.Reason+"\nresult: null\n")
		}
		if err := writeApplyPublicationText(out, "publication:\nstage: evaluated\nreason: null\nresult:\n"); err != nil {
			return err
		}
		return writeApplyPublicationBytes(out, publication)
	}
	// The complete outer compact account adds both child accounts and 256
	// bytes for the stage and envelope. Child nesting increases by at most two;
	// the closed schema stays below twelve levels. Replaying readable children
	// strips only structural whitespace and never retains a second full body.
	const compactMaximum = applyPublicationCompactLimit
	return writeReadableResultJSON(context.Background(), out, compactMaximum, ErrApplyPublicationResult, func(w *resultStreamWriter) {
		emit := func(body []byte) {
			for len(body) != 0 {
				n := min(len(body), 4096)
				w.text(string(body[:n]))
				body = body[n:]
			}
		}
		w.text(`{"schema":"ApplyPublicationResult/v1","apply":`)
		emit(apply)
		w.text(`,"publication":{"stage":`)
		w.value(result.Publication.Stage)
		if result.Publication.Stage == "unstarted" {
			w.text(`,"reason":`)
			w.value(result.Publication.Reason)
			w.text(`,"result":null}}`)
		} else {
			w.text(`,"reason":null,"result":`)
			emit(publication)
			w.text("}}")
		}
	})
}

func writeApplyPublicationText(out io.Writer, text string) error {
	n, err := io.WriteString(out, text)
	if err == nil && n != len(text) {
		return io.ErrShortWrite
	}
	return err
}

func writeApplyPublicationBytes(out io.Writer, body []byte) error {
	n, err := out.Write(body)
	if err == nil && n != len(body) {
		return io.ErrShortWrite
	}
	return err
}
