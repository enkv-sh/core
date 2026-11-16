package plugininstallation

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"enkv.sh/sdk/artifact"
)

// New binds trusted distribution/protocol checks and the current user's
// configuration directory. It copies key, redirect-host and TLS-root inputs,
// creates local storage as needed, and performs no acquisition or plugin execution.
func New(assembly Assembly) (*Coordinator, error) {
	config, err := os.UserConfigDir()
	if err != nil {
		return nil, settingsFailure("", "settings-unavailable", nil, err)
	}
	return newCoordinator(config, assembly)
}

func newCoordinator(config string, assembly Assembly) (*Coordinator, error) {
	if assembly.Check == nil || len(assembly.PluginKeys) == 0 {
		return nil, ErrInvalid
	}
	origin, err := url.Parse(assembly.Origin)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || origin.RawPath != "" || !strings.HasSuffix(origin.Path, "/") {
		return nil, ErrInvalid
	}
	directory, err := configurationDirectory(config)
	if err != nil {
		return nil, settingsFailure(filepath.Join(config, "enkv", "plugins.json"), "settings-unavailable", nil, err)
	}
	config = directory
	c := &Coordinator{configDirectory: filepath.Join(config, "enkv"), store: filepath.Join(config, "enkv", "installation"), origin: origin.String(), hosts: map[string]bool{origin.Host: true}, check: assembly.Check}
	for _, key := range assembly.PluginKeys {
		if len(key) != ed25519.PublicKeySize {
			return nil, ErrInvalid
		}
		c.keys = append(c.keys, append(ed25519.PublicKey(nil), key...))
	}
	for _, host := range assembly.RedirectHosts {
		if host == "" || strings.ContainsAny(host, "/@?#") {
			return nil, ErrInvalid
		}
		c.hosts[host] = true
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second, DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	if assembly.TLSRoots != nil {
		transport.TLSClientConfig.RootCAs = assembly.TLSRoots.Clone()
	}
	c.client = &http.Client{Transport: transport, Timeout: 2 * time.Minute, CheckRedirect: func(request *http.Request, via []*http.Request) error {
		if len(via) >= 8 || request.URL.Scheme != "https" || request.URL.User != nil || !c.hosts[request.URL.Host] {
			return ErrInvalid
		}
		request.Header = make(http.Header)
		return nil
	}}
	if err := ensureDirectory(c.store); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Coordinator) verifySignature(purpose string, body, sig []byte) error {
	for _, key := range c.keys {
		if artifact.VerifySignature(purpose, body, sig, key) == nil {
			return nil
		}
	}
	return ErrSignature
}

func (c *Coordinator) get(ctx context.Context, relative string) (*http.Response, error) {
	if !safeRelative(relative) || strings.ContainsAny(relative, "?#\\") {
		return nil, ErrInvalid
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.origin+filepath.ToSlash(relative), nil)
	if err != nil {
		return nil, err
	}
	response, err := c.client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, errors.Join(ErrMissing, response.Body.Close())
	}
	return response, nil
}

func (c *Coordinator) fetch(ctx context.Context, relative string, limit int64) (body []byte, err error) {
	response, err := c.get(ctx, relative)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, response.Body.Close())
		if err != nil {
			body = nil
		}
	}()
	if response.ContentLength > limit {
		return nil, ErrInvalid
	}
	body, err = io.ReadAll(io.LimitReader(ctxReader{ctx, response.Body}, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, ErrInvalid
	}
	return body, nil
}

func (c *Coordinator) index(ctx context.Context, name string) (artifact.ReleaseIndex, error) {
	base := "plugins/" + name + "/"
	body, err := c.fetch(ctx, base+"index.json", artifact.MaxRecordBytes)
	if err != nil {
		return artifact.ReleaseIndex{}, err
	}
	sig, err := c.fetch(ctx, base+"index.sig", 64)
	if err != nil {
		return artifact.ReleaseIndex{}, err
	}
	if err := c.verifySignature("plugin-index", body, sig); err != nil {
		return artifact.ReleaseIndex{}, err
	}
	index, err := artifact.DecodeReleaseIndex(body)
	if err != nil || index.Name != name {
		return artifact.ReleaseIndex{}, errors.Join(ErrInvalid, err)
	}
	return index, nil
}

func (c *Coordinator) acquire(ctx context.Context, relative string, expected artifact.Selection, exact bool) (installed *Installed, err error) {
	return c.acquireChecked(ctx, relative, expected, exact, nil)
}

func (c *Coordinator) acquireChecked(ctx context.Context, relative string, expected artifact.Selection, exact bool, retainedCheck Check) (installed *Installed, err error) {
	ctx, call := startCall(ctx, opAcquire)
	known := expected
	installed, err = c.acquirePackage(ctx, relative, expected, exact, retainedCheck, &known)
	finishCall(call, err)
	if err != nil {
		return nil, &candidateFailure{selection: known, cause: err}
	}
	return installed, err
}

func (c *Coordinator) acquirePackage(ctx context.Context, relative string, expected artifact.Selection, exact bool, retainedCheck Check, known *artifact.Selection) (installed *Installed, err error) {
	body, err := c.fetch(ctx, relative+"archive.json", artifact.MaxRecordBytes)
	if err != nil {
		return nil, err
	}
	sig, err := c.fetch(ctx, relative+"archive.sig", 64)
	if err != nil {
		return nil, err
	}
	if err := c.verifySignature("plugin-archive", body, sig); err != nil {
		return nil, err
	}
	record, err := artifact.DecodeArchiveRecord(body)
	if err != nil {
		return nil, errors.Join(ErrInvalid, err)
	}
	if expected.Name != "" && record.Name != expected.Name || expected.Version != "" && record.Version != expected.Version || expected.Platform != "" && record.Platform != expected.Platform || !expected.Artifact.IsZero() && record.Artifact != expected.Artifact {
		return nil, ErrIdentity
	}
	known.Name, known.Version, known.Platform, known.Artifact = record.Name, record.Version, record.Platform, record.Artifact
	stage, err := makeStage(filepath.Join(c.store, "packages", record.Artifact.String()))
	if err != nil {
		return nil, err
	}
	defer func() {
		if cleanupErr := stage.finish(); cleanupErr != nil {
			err = errors.Join(err, cleanupErr)
		}
		if err != nil {
			installed = nil
		}
	}()
	response, err := c.get(ctx, relative+record.Archive.Filename)
	if err != nil {
		return nil, err
	}
	if response.ContentLength > artifact.MaxArchiveBytes {
		return nil, errors.Join(ErrInvalid, response.Body.Close())
	}
	contents, extractErr := artifact.ExtractArchiveBytes(ctx, response.Body, record, stage.path, stage.adopt)
	closeErr := response.Body.Close()
	if extractErr != nil || closeErr != nil {
		return nil, errors.Join(extractErr, closeErr)
	}
	metadataSig, err := readFile(ctx, filepath.Join(stage.path, "metadata.sig"), 64)
	if err != nil {
		return nil, errors.Join(ErrSignature, err)
	}
	if err := c.verifySignature("plugin-executable", contents.MetadataBytes, metadataSig); err != nil {
		return nil, err
	}
	proof := artifact.OfficialProof{Schema: "enkv/plugin-official-proof/v1", Artifact: record.Artifact, ArchiveRecord: artifact.Hash(body), MetadataSignature: artifact.Hash(metadataSig), ArchiveSignature: artifact.Hash(sig)}
	proofBytes, err := artifact.EncodeOfficialProof(proof)
	if err != nil {
		return nil, err
	}
	proofID := artifact.Hash(proofBytes)
	if exact && !expected.Proof.IsZero() && proofID != expected.Proof {
		return nil, ErrIdentity
	}
	validate := func(path string, contents artifact.PackageContents) error {
		if err := c.validate(ctx, path, contents, retainedCheck != nil); err != nil {
			return err
		}
		if retainedCheck != nil {
			return retainedCheck(ctx, contents.Metadata, append([]byte(nil), contents.DependencyBytes...))
		}
		return nil
	}
	if err := validate(stage.path, contents); err != nil {
		return nil, err
	}
	selection := artifact.Selection{Name: record.Name, Version: record.Version, Platform: record.Platform, Artifact: record.Artifact, Proof: proofID}
	if err := publishStage(ctx, stage, proofID.String(), func(path string) error {
		actual, err := artifact.ReadPackageBytes(ctx, path, record)
		if err != nil {
			if stateErr := partialPackage(ctx, path, record); stateErr != nil {
				return stateErr
			}
			return err
		}
		return validate(path, actual)
	}); err != nil {
		return nil, err
	}
	proofStage, err := makeStage(filepath.Join(c.store, "proofs", record.Artifact.String()))
	if err != nil {
		return nil, err
	}
	defer func() {
		if cleanupErr := proofStage.finish(); cleanupErr != nil {
			err = errors.Join(err, cleanupErr)
		}
		if err != nil {
			installed = nil
		}
	}()
	for _, member := range []struct {
		name string
		body []byte
	}{{"proof.json", proofBytes}, {"metadata.sig", metadataSig}, {"archive.json", body}, {"archive.sig", sig}} {
		if err := proofStage.writeBytes(ctx, member.name, member.body); err != nil {
			return nil, err
		}
	}
	if err := publishStage(ctx, proofStage, proofID.String(), func(path string) error { return c.verifyProofFiles(ctx, path, selection) }); err != nil {
		return nil, err
	}
	installed, err = c.official(ctx, selection, retainedCheck != nil)
	if err == nil && retainedCheck != nil {
		metadata, _ := installed.Metadata()
		err = retainedCheck(ctx, metadata, installed.DependencyBytes())
		if err != nil {
			installed = nil
		}
	}
	return installed, err
}
