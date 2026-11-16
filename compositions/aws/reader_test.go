package compositionaws

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	core "enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/crypto/testsupport/installedarchive"
	awsprovider "enkv.sh/providers/aws"
	"errors"
	"net/http"
	"reflect"
	"slices"
	"testing"
	"time"
)

func readerConfig(t *testing.T) ReaderConfig {
	t.Helper()
	cell := localConfig(t)
	fixture, basisBytes := installedarchive.LoadReader(t, "aws")
	var basisImage struct {
		Schema     int    `json:"schema"`
		Kind       string `json:"kind"`
		Descriptor []byte `json:"descriptor"`
	}
	if err := json.Unmarshal(basisBytes, &basisImage); err != nil || basisImage.Schema != 2 || basisImage.Kind != "genesis" {
		t.Fatal("independent public fixture basis", err)
	}
	cell.Store.ExpectedBucketOwner = fixture.Archive.Location.ExpectedOwner
	cell.Store.Domain = fixture.Archive.Domain
	cell.Store.Region = fixture.Archive.Location.Region
	cell.Store.Bucket = fixture.Archive.Location.Bucket
	cell.Store.Prefix = fixture.Archive.Location.PrefixBeforeHEAD

	store, err := awsprovider.NewStore(cell.Store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (core.PublicBasis{Descriptor: basisImage.Descriptor}).ControlCore(cell.Store.Domain, store.Descriptor()); err != nil {
		t.Fatal("independent complete basis refused", err)
	}
	validator := core.NewPublicConfigurationValidator(nil)
	return ReaderConfig{Candidate: awsprovider.CandidateReadConfig{Region: cell.Store.Region, Bucket: cell.Store.Bucket, Prefix: cell.Store.Prefix, ExpectedBucketOwner: cell.Store.ExpectedBucketOwner, CredentialRoute: cell.Store.CredentialRoute, Credentials: cell.Store.Credentials, Transport: cell.Store.Transport, Timeout: cell.Store.Timeout}, ExpectedDomain: cell.Store.Domain, ExpectedStore: store.Descriptor(), PublicBasis: core.PublicBasis{Descriptor: basisImage.Descriptor}, Validator: validator}
}

// full_only: false
func TestNewReaderPinsAWSComponentsWithoutEffects(t *testing.T) {
	c := readerConfig(t)
	engine, err := NewReader(c)
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

	t.Run("default-transport", func(t *testing.T) {
		c := readerConfig(t)
		source := &http.Transport{TLSHandshakeTimeout: time.Second, ResponseHeaderTimeout: 2 * time.Second, ExpectContinueTimeout: 3 * time.Second}
		c.Candidate.Transport = source
		engine, err := NewReader(c)
		if err != nil || engine == nil {
			t.Fatal("default transport did not install Reader", err)
		}
		engine.Close()
		if source.TLSClientConfig != nil || source.TLSNextProto != nil || source.HTTP2 != nil || source.Protocols != nil {
			t.Fatal("Reader construction initialized caller protocol policy")
		}
		owned := snapshotReconstructionTransport(source)
		if owned.TLSClientConfig != nil || owned.TLSHandshakeTimeout != time.Second || owned.ResponseHeaderTimeout != 2*time.Second || owned.ExpectContinueTimeout != 3*time.Second {
			t.Fatal("snapshot changed default TLS or timeout policy")
		}
	})
	t.Run("owned-tls-policy", func(t *testing.T) {
		c := readerConfig(t)
		first := &x509.Certificate{Raw: []byte("first"), RawSubject: []byte("first")}
		second := &x509.Certificate{Raw: []byte("second"), RawSubject: []byte("second")}
		third := &x509.Certificate{Raw: []byte("third"), RawSubject: []byte("third")}
		roots, wantRoots := x509.NewCertPool(), x509.NewCertPool()
		roots.AddCert(first)
		wantRoots.AddCert(first)
		source := &http.Transport{DialContext: c.Candidate.Transport.DialContext, TLSClientConfig: &tls.Config{
			RootCAs: roots, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			NextProtos: []string{"http/1.1"}, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			CurvePreferences: []tls.CurveID{tls.CurveP256}, SessionTicketsDisabled: true, DynamicRecordSizingDisabled: true,
		}}
		owned := snapshotReconstructionTransport(source)
		source.TLSClientConfig.MinVersion = tls.VersionTLS12
		source.TLSClientConfig.NextProtos[0] = "h2"
		source.TLSClientConfig.CipherSuites[0] = tls.TLS_RSA_WITH_AES_128_GCM_SHA256
		source.TLSClientConfig.CurvePreferences[0] = tls.CurveP384
		roots.AddCert(second)
		policy := owned.TLSClientConfig
		if policy == source.TLSClientConfig || policy.RootCAs == roots || !policy.RootCAs.Equal(wantRoots) ||
			policy.MinVersion != tls.VersionTLS13 || policy.MaxVersion != tls.VersionTLS13 || !policy.SessionTicketsDisabled || !policy.DynamicRecordSizingDisabled ||
			!slices.Equal(policy.NextProtos, []string{"http/1.1"}) || !slices.Equal(policy.CipherSuites, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}) || !slices.Equal(policy.CurvePreferences, []tls.CurveID{tls.CurveP256}) {
			t.Fatal("snapshot did not own the admitted TLS policy")
		}
		c.Candidate.Transport = owned
		engine, err := NewReader(c)
		if err != nil || engine == nil {
			t.Fatal("owned stronger TLS policy did not install Reader", err)
		}
		engine.Close()
		policy.NextProtos[0], policy.CipherSuites[0], policy.CurvePreferences[0] = "owned-only", tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, tls.CurveP521
		policy.RootCAs.AddCert(third)
		wantRoots.AddCert(second)
		if source.TLSClientConfig.NextProtos[0] != "h2" || source.TLSClientConfig.CipherSuites[0] != tls.TLS_RSA_WITH_AES_128_GCM_SHA256 || source.TLSClientConfig.CurvePreferences[0] != tls.CurveP384 || !roots.Equal(wantRoots) {
			t.Fatal("owned policy mutation reached the caller")
		}
	})
	for _, hook := range []string{"Dial", "DialTLS", "DialTLSContext"} {
		t.Run("refused-hook/"+hook, func(t *testing.T) {
			c := readerConfig(t)
			source := &http.Transport{}
			field := reflect.ValueOf(source).Elem().FieldByName(hook)
			field.Set(reflect.MakeFunc(field.Type(), func([]reflect.Value) []reflect.Value {
				t.Fatal("construction invoked a refused dial hook")
				return nil
			}))
			owned := snapshotReconstructionTransport(source)
			field.SetZero()
			c.Candidate.Transport = owned
			engine, err := NewReader(c)
			if engine != nil {
				engine.Close()
			}
			if !errors.Is(err, awsprovider.ErrConstruction) || engine != nil {
				t.Fatal("snapshot lost a refused dial hook", err)
			}
		})
	}
	var private bytes.Buffer
	callbackCalls := 0
	for _, tc := range []struct {
		name   string
		policy *tls.Config
		change func(*tls.Config)
	}{
		{"callback", &tls.Config{VerifyConnection: func(tls.ConnectionState) error { callbackCalls++; return nil }}, func(c *tls.Config) { c.VerifyConnection = nil }},
		{"key-log", &tls.Config{KeyLogWriter: &private}, func(c *tls.Config) { c.KeyLogWriter = nil }},
		{"client-certificate", &tls.Config{Certificates: []tls.Certificate{{}}}, func(c *tls.Config) { c.Certificates = nil }},
		{"insecure-verification", &tls.Config{InsecureSkipVerify: true}, func(c *tls.Config) { c.InsecureSkipVerify = false }},
		{"alpn", &tls.Config{NextProtos: []string{"h2"}}, func(c *tls.Config) { c.NextProtos[0] = "http/1.1" }},
	} {
		t.Run("refused-tls/"+tc.name, func(t *testing.T) {
			c := readerConfig(t)
			source := &http.Transport{TLSClientConfig: tc.policy}
			owned := snapshotReconstructionTransport(source)
			tc.change(source.TLSClientConfig)
			c.Candidate.Transport = owned
			engine, err := NewReader(c)
			if engine != nil {
				engine.Close()
			}
			if !errors.Is(err, awsprovider.ErrConstruction) || engine != nil || private.Len() != 0 || callbackCalls != 0 {
				t.Fatal("snapshot lost refused TLS evidence or invoked private output", tc.name, err)
			}
		})
	}
}

// full_only: false
func TestNewReaderRejectsUnfixedAWSInputs(t *testing.T) {
	for _, name := range []string{"domain", "Store", "basis", "mixed basis", "interpretation", "route", "location", "credentials"} {
		t.Run(name, func(t *testing.T) {
			c := readerConfig(t)
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
				c.Candidate.CredentialRoute = contract.ID{}
			case "location":
				c.Candidate.Region = ""
			case "credentials":
				c.Candidate.Credentials = nil
			}
			engine, err := NewReader(c)
			if engine != nil {
				engine.Close()
			}
			if err == nil || engine != nil {
				t.Fatal("unfixed Reader installed", err)
			}
		})
	}
}
