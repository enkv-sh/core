package compositionfull

import (
	"context"
	"encoding/json"

	"enkv.sh/compositions/configuration"
	"enkv.sh/compositions/full/plugininstallation"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	manifest "enkv.sh/sdk/manifest-generator"
)

const manifestTestFormat = "private-format/v1"

func manifestTestScope(selection manifest.Selection) *contract.ManifestRequestScope {
	return &contract.ManifestRequestScope{Renderer: contract.ManifestRendererSelection{Name: "private-renderer", Version: "1.0.0", ProtocolID: contract.ID{1}, DescriptorID: contract.ID{2}, ExecutorID: contract.ID{3}, ArtifactContractID: contract.ID{4}, DependencyManifestID: contract.ID{5}, ArtifactID: contract.ID{6}, ArtifactSHA256: contract.ID{7}, ArtifactLength: 1}, FormatContractID: manifestTestFormat, ConfigContractID: "private-settings/v1", Settings: []byte(`{}`), Selection: selection}
}
func manifestTestArtifactIdentity(format string) ManifestArtifact {
	return ManifestArtifact{RendererArtifactID: contract.ID{6}, FormatContractID: format}
}

type manifestTestDestination struct {
	ServiceContractID string `json:"service_contract_id"`
	ConsumerLocator   string `json:"consumer_locator"`
}
type manifestTestEntry struct {
	Name         string                    `json:"name"`
	PlainValue   []byte                    `json:"plain_value"`
	Destinations []manifestTestDestination `json:"destinations"`
}
type manifestTestDocument struct {
	Format        string              `json:"format"`
	ServiceFilter *string             `json:"service_filter"`
	Entries       []manifestTestEntry `json:"entries"`
}

// Reader tests install this public callback explicitly. Native artifact and
// installation checks use their own separate process fixtures.
func manifestTestRender(ctx context.Context, view manifest.View) manifest.Result {
	document := manifestTestDocument{Format: view.Header().FormatContractID, Entries: make([]manifestTestEntry, view.EntryCount())}
	header := view.Header()
	if header.HasServiceFilter {
		document.ServiceFilter = &header.ServiceFilter
	}
	var window [manifest.PlainWindowBytes]byte
	for i := range document.Entries {
		entry, ok := view.Entry(i)
		if !ok {
			return manifest.Result{Failure: manifest.InvalidInput}
		}
		metadata := entry.Metadata()
		row := &document.Entries[i]
		row.Name = metadata.Name
		if metadata.Kind == manifest.Plain {
			row.PlainValue = make([]byte, entry.PlainLength())
			for at := 0; at < len(row.PlainValue); {
				n, failure := entry.CopyPlain(at, window[:min(len(window), len(row.PlainValue)-at)])
				if failure != "" || n == 0 {
					return manifest.Result{Failure: manifest.InvalidInput}
				}
				copy(row.PlainValue[at:], window[:n])
				at += n
			}
		}
		row.Destinations = make([]manifestTestDestination, entry.DestinationCount())
		for j := range row.Destinations {
			destination, ok := entry.Destination(j)
			if !ok {
				return manifest.Result{Failure: manifest.InvalidInput}
			}
			facts := destination.Metadata()
			row.Destinations[j] = manifestTestDestination{facts.ServiceContractID, facts.ConsumerLocator}
		}
	}
	if ctx.Err() != nil {
		return manifest.Result{Failure: manifest.Cancelled}
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return manifest.Result{Failure: manifest.InvalidResult}
	}
	owned := make([]byte, len(encoded))
	copy(owned, encoded)
	return manifest.Result{Artifact: owned}
}

func manifestTestCapture(_ context.Context, _ *configuration.Pair, requirement plugininstallation.Requirement, options ManifestOptions) (contract.ManifestRequest, func(context.Context, contract.ManifestRendererSelection) (manifest.Renderer, manifest.Failure), error) {
	scope := manifestTestScope(manifest.Selection{TargetMode: options.TargetMode, EntryMode: options.EntryMode})
	scope.Renderer.Name = options.Plugin
	scope.FormatContractID = options.Plugin
	request, err := contract.OwnManifestRequest(contract.ManifestRequest{Renderer: scope.Renderer, FormatContractID: scope.FormatContractID, ConfigContractID: scope.ConfigContractID, Settings: options.Settings, TargetMode: options.TargetMode, EntryMode: options.EntryMode, TargetRecipientID: options.TargetRecipientID, EntryNames: options.EntryNames, ServiceFilter: options.ServiceFilter})
	if err != nil {
		return contract.ManifestRequest{}, nil, err
	}
	prepare := func(_ context.Context, selected contract.ManifestRendererSelection) (manifest.Renderer, manifest.Failure) {
		if selected != scope.Renderer || requirement.Name != options.Plugin {
			return nil, manifest.InvalidInput
		}
		return manifestTestRender, ""
	}
	return request, prepare, nil
}
func issueTestConfigurationManifest(ctx context.Context, nonce contract.ID, pair *configuration.Pair, options ManifestOptions, open manifestReaderOpener) (core.PublicManifestResult, error) {
	return issueConfigurationManifest(ctx, nonce, pair, options, open, manifestTestCapture)
}
func issueTestConfigurationManifestFile(ctx context.Context, nonce contract.ID, path string, format configuration.Format, options ManifestOptions, open manifestReaderOpener, closePair func(*configuration.Pair) error) (core.PublicManifestResult, error) {
	return issueConfigurationManifestFile(ctx, nonce, path, format, options, open, manifestTestCapture, closePair)
}
func writeTestConfigurationManifest(ctx context.Context, nonce contract.ID, pair *configuration.Pair, options ManifestOptions, path string, open manifestReaderOpener) ManifestFileResult {
	return writeConfigurationManifest(ctx, nonce, pair, options, path, open, manifestTestCapture)
}
func writeTestConfigurationManifestFile(ctx context.Context, nonce contract.ID, path string, format configuration.Format, options ManifestOptions, out string, open manifestReaderOpener, closePair func(*configuration.Pair) error) ManifestFileResult {
	return writeConfigurationManifestFile(ctx, nonce, path, format, options, out, open, manifestTestCapture, closePair)
}
