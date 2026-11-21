package compositionfull

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	compositionaws "enkv.sh/compositions/aws"
	compositiongcp "enkv.sh/compositions/gcp"
	"enkv.sh/core"
	"enkv.sh/core/contract"
	"enkv.sh/core/format"
	"enkv.sh/crypto/testsupport/installedarchive"
	genericjson "enkv.sh/plugins/manifest-generators/generic-json"
	awsprovider "enkv.sh/providers/aws"
	gcpprovider "enkv.sh/providers/gcp"
	manifestsdk "enkv.sh/sdk/manifest-generator"
	"enkv.sh/telemetry"
	"github.com/aws/aws-sdk-go-v2/aws"
)

type readerFixtureProfile struct {
	destination, provider, slot, locator string
	policy                               contract.OutputPolicy
}

func readerFixtureProfiles(entry ...string) []readerFixtureProfile {
	name := "secret"
	if len(entry) != 0 {
		name = entry[0]
	}
	upper := strings.ToUpper(name)
	suffix := map[string]string{"secret": "AbCd12", "encoded": "XyZ123"}[name]
	awsSlot := "arn:aws:secretsmanager:us-east-1:123456789012:secret:" + name
	gcpSlot := "projects/123456789/secrets/" + name
	return []readerFixtureProfile{
		{destination: "aws", provider: "aws-secrets-manager", slot: awsSlot, locator: awsSlot + "-" + suffix + "?stage=AWSCURRENT"},
		{destination: "gcp", provider: "gcp-secret-manager", slot: gcpSlot, locator: gcpSlot + "/versions/latest"},
		{destination: "github-environment", provider: "github-actions", slot: "repos/owner/repo/environments/prod/secrets/" + upper, locator: "repos/owner/repo/environments/prod/secrets/" + upper},
		{destination: "github-organization", provider: "github-actions", slot: "orgs/owner/actions/secrets/" + upper, locator: "orgs/owner/actions/secrets/" + upper, policy: contract.OutputPolicy{ContractID: "fixture/organization-policy/v1", Data: []byte{1, 7, 11}}},
		{destination: "github-repository", provider: "github-actions", slot: "repos/owner/repo/actions/secrets/" + upper, locator: "repos/owner/repo/actions/secrets/" + upper},
	}
}

func readerFixtureDestination(profile readerFixtureProfile) contract.OutputDestination {
	caps := contract.OutputCapabilityCreateEmpty | contract.OutputCapabilityCreateWithValue | contract.OutputCapabilityWriteValue | contract.OutputCapabilityUpdatePolicy | contract.OutputCapabilityDeleteOwned | contract.OutputCapabilityDeleteReservedSlot
	if profile.policy.ContractID != "" {
		caps |= contract.OutputCapabilityCreateSetsPolicy | contract.OutputCapabilityWriteSetsPolicy
	}
	return contract.OutputDestination{ConfigContractID: "fixture/" + profile.destination + "/config/v1", ServiceContractID: profile.provider, CanonicalSettings: []byte(`{"destination":"` + profile.destination + `"}`), Policy: profile.policy, Capabilities: caps}
}
func readerFixtureOutputTarget(profile readerFixtureProfile, encoding uint8) contract.OutputTarget {
	caps := readerFixtureDestination(profile).Capabilities
	locator := profile.locator
	assigned := profile.destination == "aws"
	if assigned {
		locator = ""
	}
	return contract.OutputTarget{ServiceContractID: profile.provider, TargetContractID: "fixture/target/v1", CanonicalTarget: profile.slot, ConsumerLocator: locator, TargetData: []byte("target:" + profile.slot), PayloadEncoding: encoding, LocatorRequiresCreation: assigned, Capabilities: caps, CreateValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, WriteValueBounds: contract.OutputPayloadBounds{Maximum: 65536}, Policy: profile.policy}
}

func readerFixtureInterpretOutput(_ context.Context, id string, destination contract.OutputDestination, name string, encoding uint8) (contract.OutputTarget, error) {
	for _, profile := range readerFixtureProfiles(name) {
		if id == profile.destination && reflect.DeepEqual(destination, readerFixtureDestination(profile)) {
			return readerFixtureOutputTarget(profile, encoding), nil
		}
	}
	return contract.OutputTarget{}, contract.ErrRecord
}

// This expectation frames the two policy blobs independently of the Product codecs.
func readerFixturePolicyJSON(domain contract.ID, policy contract.OutputPolicy) string {
	if policy.ContractID == "" {
		return "null"
	}
	preimage := append([]byte("ENKV/OUTPUT/POLICY/v3\x00"), domain[:]...)
	preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(policy.ContractID)))
	preimage = append(preimage, policy.ContractID...)
	preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(policy.Data)))
	preimage = append(preimage, policy.Data...)
	digest := sha256.Sum256(preimage)
	return fmt.Sprintf(`{"contract_id":%q,"data_base64":%q,"digest":"%x"}`, policy.ContractID, base64.StdEncoding.EncodeToString(policy.Data), digest)
}

type readerHTTPFixture struct {
	mu                      sync.Mutex
	archive                 installedarchive.Archive
	reads                   map[string]int
	forbidden, failedWrites int
	unavailable             bool
	damagedKey              string
	damageAt                int
}

func (h *readerHTTPFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	a := h.archive
	var prefix, host string
	if a.Family == contract.AWS {
		prefix = "/" + a.Location.Bucket + "/"
		host = "s3." + a.Location.Region + ".amazonaws.com"
	} else {
		prefix = "/download/storage/v1/b/" + a.Location.Bucket + "/o/"
		host = "storage." + a.Location.Region + ".rep.googleapis.com"
	}
	if r.Method != http.MethodGet || r.Host != host || !strings.HasPrefix(r.URL.Path, prefix) || r.Header.Get("Authorization") == "" || a.Family == contract.GCP && r.URL.Query().Get("alt") != "media" {
		h.forbidden++
		http.Error(w, "raw-error-sentinel secret-sentinel", http.StatusForbidden)
		return
	}
	key := strings.TrimPrefix(r.URL.Path, prefix)
	h.reads[key]++
	if h.unavailable {
		http.Error(w, "raw-error-sentinel secret-sentinel", http.StatusServiceUnavailable)
		return
	}
	object, ok := a.Object(key)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if a.Family == contract.AWS {
		w.Header().Set("ETag", object.Token.Value)
	} else {
		w.Header().Set("X-Goog-Generation", object.Token.Value)
	}
	body := object.Body
	if key == h.damagedKey && h.reads[key] == h.damageAt {
		body = bytes.Clone(body)
		body[len(body)-1] ^= 1
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Content-Type", "application/octet-stream")
	if _, err := w.Write(body); err != nil {
		h.failedWrites++
	}
}
func (h *readerHTTPFixture) reset(unavailable bool, key string, at int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.reads = make(map[string]int)
	h.unavailable = unavailable
	h.damagedKey = key
	h.damageAt = at
}
func (h *readerHTTPFixture) count(key string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.reads[key]
}
func (h *readerHTTPFixture) assertNoEffects(t *testing.T) {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.forbidden != 0 || h.failedWrites != 0 {
		t.Fatal("Reader made forbidden or unjoined HTTP work", h.forbidden, h.failedWrites)
	}
}
func readerHTTPTransport(t *testing.T, h http.Handler, hosts []string) (*http.Transport, func()) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: hosts, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(h)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "tcp", server.Listener.Addr().String())
	}}
	close := func() { transport.CloseIdleConnections(); server.Close() }
	t.Cleanup(close)
	return transport, close
}

type readerFixtureCredentials struct{}

func (readerFixtureCredentials) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{AccessKeyID: "local-access", SecretAccessKey: "local-secret"}, nil
}
func (readerFixtureCredentials) Token(context.Context) (string, error) {
	return "local-read-token", nil
}

func readerFixtureTarget(domain contract.ID) contract.ID {
	// Independent fixture identity recipe: SHA-256("fixture/" || domain || "/reader").
	body := append([]byte("fixture/"), domain[:]...)
	return contract.ID(sha256.Sum256(append(body, []byte("/reader")...)))
}
func readerFixtureInput(basis contract.GenesisDescriptorCore, family contract.Family) contract.PublicConfiguration {
	members := []contract.ID{basis.AuthorityRecipientID, readerFixtureTarget(basis.DomainID)}
	slices.SortFunc(members, func(a, b contract.ID) int { return bytes.Compare(a[:], b[:]) })
	region, owner := "australia-southeast1", ""
	if family == contract.AWS {
		region, owner = "us-east-1", "123456789012"
	}
	signing := basis.NormalSigning
	desired := contract.PublicConfiguration{
		Entries: readerPresent([]contract.PublicEntry{
			{Name: "", Class: readerPresent(uint8(contract.Plain)), Source: readerPresent(uint8(contract.Supplied)), PlainValue: readerPresent([]byte{}), Memberships: readerPresent(members)},
			{Name: "a/\n雪", Class: readerPresent(uint8(contract.Plain)), Source: readerPresent(uint8(contract.Supplied)), PlainValue: readerPresent([]byte{0, 10, 65}), Memberships: readerPresent(members)},
			{Name: "encoded", OutputEncoding: readerPresent(contract.OutputEncodingBase64), Class: readerPresent(uint8(contract.Secret)), Source: readerPresent(uint8(contract.Supplied)), Memberships: readerPresent(members)},
			{Name: "secret", Class: readerPresent(uint8(contract.Secret)), Source: readerPresent(uint8(contract.Supplied)), Memberships: readerPresent(members)},
		}),
		Recipients: readerPresent([]contract.PublicRecipient{}), OutputBindings: readerPresent([]contract.PublicOutputBinding{}), Routing: readerPresent([]contract.PublicRoutingRule{}),
		Store:     contract.PublicStoreSettings{DomainID: readerPresent(basis.DomainID), Provider: readerPresent(family), ConstructionProfile: readerPresent(uint16(contract.StoreConstructionProfile)), Region: readerPresent(region), Bucket: readerPresent("fixture-bucket"), Prefix: readerPresent("fixture"), ExpectedOwner: readerPresent(owner)},
		Authority: contract.PublicAuthoritySettings{RecipientID: readerPresent(basis.AuthorityRecipientID), Signing: contract.PublicSigningSettings{Provider: readerPresent(signing.Provider), Selector: readerPresent(signing.KeySelector), PublicKey: readerPresent(signing.SPKI), Fingerprint: readerPresent(signing.Fingerprint), Role: readerPresent(signing.Role), Profile: readerPresent(signing.SigningProfile)}},
		Recovery:  contract.PublicRecoverySettings{Enabled: readerPresent(false)},
	}
	for _, recipient := range basis.Recipients {
		key := recipient.CurrentBinding
		desired.Recipients.Value = append(desired.Recipients.Value, contract.PublicRecipient{RecipientID: recipient.RecipientID, DisplayName: readerPresent(recipient.DisplayName), Encryption: contract.PublicEncryptionSettings{Provider: readerPresent(key.Provider), Selector: readerPresent(key.KeySelector), PublicKey: readerPresent(key.SPKI), Fingerprint: readerPresent(key.Fingerprint), WrapProfile: readerPresent(key.WrapProfile), ProtectionClass: readerPresent(key.ProtectionClass)}})
	}
	var destinations []string
	for index, profile := range readerFixtureProfiles() {
		var targets []contract.PublicOutputTarget
		for _, name := range []string{"encoded", "secret"} {
			exact := readerFixtureProfiles(name)[index]
			encoding := uint8(contract.OutputEncodingRaw)
			if name == "encoded" {
				encoding = contract.OutputEncodingBase64
			}
			targets = append(targets, reconstructionPublicTarget(name, readerFixtureOutputTarget(exact, encoding)))
		}
		desired.OutputBindings.Value = append(desired.OutputBindings.Value, contract.PublicOutputBinding{DestinationID: profile.destination, Destination: readerPresent(readerFixtureDestination(profile)), Targets: readerPresent(targets)})
		destinations = append(destinations, profile.destination)
	}
	desired.Routing.Value = []contract.PublicRoutingRule{
		{Key: contract.PublicRoutingKey{EntrySelector: contract.PublicDefaultRoute}, Destinations: readerPresent(destinations)},
		{Key: contract.PublicRoutingKey{EntrySelector: contract.PublicNamedEntry, EntryName: ""}, Destinations: readerPresent([]string{})},
		{Key: contract.PublicRoutingKey{EntrySelector: contract.PublicNamedEntry, EntryName: "a/\n雪"}, Destinations: readerPresent([]string{})},
		{Key: contract.PublicRoutingKey{EntrySelector: contract.PublicNamedEntry, EntryName: "encoded"}, Destinations: readerPresent(destinations)},
	}

	return desired
}

func readerFixtureFacts(t *testing.T, a installedarchive.Archive) (format.Head, format.Root, map[string]contract.ID, map[string]contract.ID, string) {
	t.Helper()
	parts, err := a.SelectedParts()
	if err != nil {
		t.Fatal(err)
	}
	var head format.Head
	var root format.Root
	entries := make(map[string]contract.ID)
	bindings := make(map[string]contract.ID)
	var slices []contract.OutputConfigurationSlice
	var outputKey string
	for _, part := range parts {
		switch part.Kind {
		case "HEAD":
			head, err = format.DecodeHead(part.Body)
		case "root":
			root, err = format.DecodeRoot(part.Body)
		case "value page":
			var page format.ValueEntryPage
			page, err = format.DecodeValueEntryPage(part.Body)
			for _, entry := range page.Slots {
				if entry != nil {
					entries[entry.Name] = entry.Incarnation
				}
			}
		case "support row":
			if part.SupportKind == contract.OutputConfigurationSliceSupportKind {
				var slice contract.OutputConfigurationSlice
				slice, err = contract.InspectOutputConfigurationSlice(part.Body)
				if err != nil {
					t.Fatal("fixture output slice refused", err)
				}
				slices = append(slices, slice)
				outputKey, err = format.Key(a.Location.PrefixBeforeHEAD, part.Ref)
			}
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	image, err := contract.JoinOutputConfiguration(a.Domain, root.OutputConfiguration, slices)
	if err != nil {
		t.Fatal(err)
	}
	output, _, err := contract.InspectOutputConfiguration(a.Domain, image)
	if err != nil {
		t.Fatal(err)
	}
	for _, binding := range output.Bindings {
		bindings[binding.DestinationID] = binding.IncarnationID
	}
	if len(entries) != 4 || len(bindings) != 5 || outputKey == "" {
		t.Fatal("mixed fixture facts differ")
	}
	return head, root, entries, bindings, outputKey
}
func readerExpectedManifest(t *testing.T, head format.Head, root format.Root, target contract.ID, entries, bindings map[string]contract.ID, empty bool) string {
	t.Helper()
	formatExpected := func(compact string) string {
		var formatted bytes.Buffer
		if err := json.Indent(&formatted, []byte(compact), "", "  "); err != nil {
			t.Fatal("independent expected manifest is invalid", err)
		}
		formatted.WriteByte('\n')
		return formatted.String()
	}
	id := func(v contract.ID) string { return hex.EncodeToString(v[:]) }
	envelope := fmt.Sprintf(`{"schema":"ENKV/CONSUMPTION-MANIFEST/v3","format_contract_id":"ENKV/CONSUMPTION-MANIFEST/v3","config_contract_id":"ENKV/CONSUMPTION-MANIFEST-CONFIG/v1","observation":{"domain_id":"%s","head_revision_id":"%s","snapshot_id":"%s"},"target_recipient_id":"%s","selection":{"target_mode":"exact-recipient","entry_mode":"exact-names"},"service_filter":null,"entries":[`, id(root.Domain), id(head.Core.Revision), id(root.Snapshot), id(target))
	if empty {
		return formatExpected(envelope + `],"excluded_entries":[],"evidence_limit":"authorized-input-and-exact-bytes"}`)
	}
	envelope += fmt.Sprintf(`{"name":"","entry_incarnation_id":"%s","content":{"kind":"plain","value_base64":""}},{"name":"a/\n雪","entry_incarnation_id":"%s","content":{"kind":"plain","value_base64":"AApB"}}`, id(entries[""]), id(entries["a/\n雪"]))
	for _, name := range []string{"encoded", "secret"} {
		encoding := "raw"
		if name == "encoded" {
			encoding = "base64"
		}
		envelope += fmt.Sprintf(`,{"name":"%s","entry_incarnation_id":"%s","content":{"kind":"secret","destinations":[`, name, id(entries[name]))
		for index, profile := range readerFixtureProfiles(name) {
			if index != 0 {
				envelope += ","
			}
			envelope += fmt.Sprintf(`{"destination_id":"%s","binding_incarnation_id":"%s","entry_incarnation_id":"%s","service_contract_id":"%s","consumer_locator":"%s","target_contract_id":"fixture/target/v1","canonical_target":"%s","target_data_base64":"%s","payload_encoding":"%s","consumer_policy":%s}`, profile.destination, id(bindings[profile.destination]), id(entries[name]), profile.provider, profile.locator, profile.slot, base64.StdEncoding.EncodeToString([]byte("target:"+profile.slot)), encoding, readerFixturePolicyJSON(root.Domain, profile.policy))
		}
		envelope += `]}}`
	}
	return formatExpected(envelope + `],"excluded_entries":[],"evidence_limit":"authorized-input-and-exact-bytes"}`)
}

func assertReaderRenderings(t *testing.T, r ConfigurationComparisonResult) {
	t.Helper()
	machine, err := RenderComparisonJSON(r)
	if err != nil {
		t.Fatal("comparison JSON", err)
	}
	human, err := RenderComparisonHuman(r)
	if err != nil {
		t.Fatal("comparison human", err)
	}
	var decoded struct {
		State   contract.ReaderStateResult `json:"state_result"`
		Payload struct {
			Verdict     contract.ComparisonVerdict `json:"verdict"`
			Complete    bool                       `json:"diagnostics_complete"`
			Diagnostics []json.RawMessage          `json:"diagnostics"`
		} `json:"payload"`
	}
	if json.Unmarshal(machine, &decoded) != nil || decoded.State != r.StateResult || decoded.Payload.Verdict != r.Verdict || decoded.Payload.Complete != r.DiagnosticsComplete || len(decoded.Payload.Diagnostics) != len(r.Diagnostics) {
		t.Fatal("machine result changed facts")
	}
	var humanRecords []string
	for _, line := range strings.Split(string(human), "\n") {
		if strings.HasPrefix(line, "Issue ") {
			humanRecords = append(humanRecords, line)
		}
	}
	if len(humanRecords) != len(r.Diagnostics) {
		t.Fatal("human/machine diagnostic counts differ")
	}
	for i, row := range decoded.Payload.Diagnostics {
		assertReaderDiagnosticRecord(t, row, r.Diagnostics[i])
		diagnostic := r.Diagnostics[i]
		line := humanRecords[i]
		if !strings.HasPrefix(line, "Issue "+strings.ReplaceAll(string(diagnostic.Subject.Kind), "_", " ")) {
			t.Fatal("human diagnostic subject kind differs", i)
		}
		var facts []string
		subject := diagnostic.Subject
		if subject.Kind == contract.SubjectEntry || subject.Kind == contract.SubjectOutputTarget {
			facts = append(facts, fmt.Sprintf(" %q", subject.Name))
		}
		if subject.DestinationID != "" {
			facts = append(facts, fmt.Sprintf(" destination %q", subject.DestinationID))
		}
		if !subject.RecipientID.IsZero() {
			facts = append(facts, fmt.Sprintf(" recipient %x", subject.RecipientID[:]))
		}
		if subject.Kind == contract.SubjectRoutingRule {
			switch subject.RoutingKey.EntrySelector {
			case contract.PublicNamedEntry:
				facts = append(facts, fmt.Sprintf(" entry %q", subject.RoutingKey.EntryName))
			case contract.PublicDefaultRoute:
				facts = append(facts, " default route")
			}
		}
		fields := make([]string, len(diagnostic.Path))
		for index, field := range diagnostic.Path {
			fields[index] = string(field)
		}
		facts = append(facts, "; field "+strings.Join(fields, ".")+": "+string(diagnostic.Outcome)+"; "+string(diagnostic.Reason))
		if source := diagnostic.SourceLocation; source != nil {
			facts = append(facts, fmt.Sprintf("; source %q location %d:%d", source.SourceID, source.Line, source.Column))
		}
		for _, fact := range facts {
			if !strings.Contains(line, fact) {
				t.Fatalf("human diagnostic %d lost exact fact %q", i, fact)
			}
		}
	}
	for _, body := range [][]byte{machine, human} {
		if bytes.Contains(body, []byte("secret-sentinel")) || bytes.Contains(body, []byte("raw-error-sentinel")) || bytes.Contains(body, []byte("enkv first secret test value")) {
			t.Fatal("result disclosed source or raw provider error")
		}
	}
}

// full_only: false
func TestInstalledReaderCompositionsCompareAndIssueFiveDestinationManifest(t *testing.T) {
	for _, familyName := range []string{"aws", "gcp"} {
		t.Run(familyName, func(t *testing.T) {
			t.Setenv("GOOGLE_API_USE_CLIENT_CERTIFICATE", "false")
			t.Setenv("EXPERIMENTAL_GOOGLE_API_USE_S2A", "false")
			fixture, basisBytes := installedarchive.LoadReader(t, familyName)
			a := fixture.Archive
			var public struct {
				Schema     int    `json:"schema"`
				Kind       string `json:"kind"`
				Descriptor []byte `json:"descriptor"`
			}
			if json.Unmarshal(basisBytes, &public) != nil || public.Schema != 2 || public.Kind != "genesis" {
				t.Fatal("independent basis fixture refused")
			}
			basis, err := contract.DecodeGenesisDescriptorCore(public.Descriptor)
			if err != nil {
				t.Fatal(err)
			}
			if basis.DomainID != a.Domain || basis.Provider != a.Family {
				t.Fatal("fixture differs from independent setup basis")
			}
			desired := readerFixtureInput(basis, a.Family)
			descriptor := contract.Descriptor{Family: a.Family, Identity: basis.StoreID, Coordinate: basis.CoordinateID, NonBody: basis.NonBodyID, Prefix: "fixture", HeadKey: "fixture/HEAD"}
			publicBasis := core.PublicBasis{Descriptor: bytes.Clone(public.Descriptor)}
			h := &readerHTTPFixture{archive: a, reads: make(map[string]int)}
			transport, stop := readerHTTPTransport(t, h, []string{"s3.us-east-1.amazonaws.com", "storage.australia-southeast1.rep.googleapis.com"})
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			var config ReaderConfig
			if a.Family == contract.AWS {
				config = ReaderConfig{Family: contract.AWS, AWS: &compositionaws.ReaderConfig{Candidate: awsprovider.CandidateReadConfig{Region: "us-east-1", Bucket: "fixture-bucket", Prefix: "fixture", ExpectedBucketOwner: "123456789012", CredentialRoute: contract.Hash([]byte("Reader AWS GET route")), Credentials: readerFixtureCredentials{}, Transport: transport, Timeout: 10 * time.Second}, ExpectedDomain: basis.DomainID, ExpectedStore: descriptor, PublicBasis: publicBasis}}
			} else {
				client, err := gcpprovider.NewLocalResponderClient(transport, readerFixtureCredentials{})
				if err != nil {
					t.Fatal(err)
				}
				config = ReaderConfig{Family: contract.GCP, GCP: &compositiongcp.ReaderConfig{Candidate: gcpprovider.CandidateReadConfig{Client: client, Region: "australia-southeast1", Bucket: "fixture-bucket", Prefix: "fixture", CredentialRoute: "Reader GCP GET route"}, ExpectedDomain: basis.DomainID, ExpectedStore: descriptor, PublicBasis: publicBasis}}
			}
			config.InterpretOutput = readerFixtureInterpretOutput
			config.PrepareManifestRenderer = func(context.Context, contract.ManifestRendererSelection) (manifestsdk.Renderer, manifestsdk.Failure) {
				return genericjson.Render, ""
			}
			engine, err := NewReader(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			defer engine.Close()
			publicBasis.Descriptor[0] ^= 1 // Constructor must own the supplied public basis.
			head, root, entries, bindings, outputKey := readerFixtureFacts(t, a)
			target := readerFixtureTarget(basis.DomainID)
			requestID := contract.Hash([]byte("Reader comparison request"))
			compared := ConfigurationComparisonResult{PublicComparisonResult: engine.Compare(ctx, requestID, desired), InstallationRequirements: InstallationRequirementComparison{Differences: []InstallationRequirementDifference{}}}
			if compared.Verdict != contract.ComparisonMatch || compared.StateResult != contract.ReaderSuccess || compared.Observation == nil || !compared.DiagnosticsComplete || len(compared.Diagnostics) != 0 || compared.Observation.HeadRevisionID != head.Core.Revision || compared.Observation.SnapshotID != root.Snapshot || ComparisonExitCode(compared) != 0 {
				t.Fatal("complete installed comparison", compared)
			}
			if len(compared.CheckedScope) != 12 {
				t.Fatal("comparison scope is incomplete")
			}
			for _, scope := range compared.CheckedScope {
				if scope.Status != contract.ScopeComplete {
					t.Fatal("match has unchecked scope")
				}
			}
			if compared.Context.OperationID.IsZero() {
				t.Fatal("comparison operation identity missing")
			}

			assertReaderRenderings(t, compared)
			finalOutputRead := h.count(outputKey)
			if finalOutputRead < 2 {
				t.Fatal("fixture does not exercise authenticated output reread")
			}

			manifest := engine.Manifest(ctx, contract.Hash([]byte("Reader manifest request")), contract.ManifestRequest{Renderer: manifestTestScope(manifestsdk.Selection{}).Renderer, FormatContractID: genericjson.FormatContractID, ConfigContractID: genericjson.ConfigContractID, Settings: []byte(`{}`), TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames, TargetRecipientID: target, EntryNames: []string{"secret", "encoded", "a/\n雪", ""}})
			want := readerExpectedManifest(t, head, root, target, entries, bindings, false)
			if manifest.StateResult != contract.ReaderSuccess || manifest.Payload == nil || manifest.TargetRecipientID != target || string(manifest.Artifact) != want || len(manifest.Artifact) != cap(manifest.Artifact) || manifest.Payload.ArtifactDigest != contract.ID(sha256.Sum256([]byte(want))) || manifest.Payload.ArtifactLength != uint64(len(want)) {
				t.Fatal("installed mixed complete manifest", manifest.StateResult, manifest.FailureReason, string(manifest.Artifact))
			}
			if manifest.Context.OperationID == compared.Context.OperationID {
				t.Fatal("operations share request identity")
			}
			consumeReaderManifest(t, manifest.Artifact)
			for _, provider := range []string{"aws-secrets-manager", "gcp-secret-manager", "github-actions"} {
				filtered := engine.Manifest(ctx, contract.Hash([]byte("filtered "+string(provider))), contract.ManifestRequest{Renderer: manifestTestScope(manifestsdk.Selection{}).Renderer, FormatContractID: genericjson.FormatContractID, ConfigContractID: genericjson.ConfigContractID, Settings: []byte(`{}`), TargetMode: manifestsdk.ExactRecipient, TargetRecipientID: target, EntryMode: manifestsdk.AllAuthorized, ServiceFilter: &provider})
				var doc struct {
					Selection manifestsdk.Selection `json:"selection"`
					Provider  *string               `json:"service_filter"`
					Entries   []struct {
						Name    string `json:"name"`
						Content struct {
							Kind         string `json:"kind"`
							Destinations []struct {
								ID       string          `json:"destination_id"`
								Provider string          `json:"service_contract_id"`
								Locator  string          `json:"consumer_locator"`
								Policy   json.RawMessage `json:"consumer_policy"`
							} `json:"destinations"`
						} `json:"content"`
					} `json:"entries"`
					Excluded []json.RawMessage `json:"excluded_entries"`
				}
				if filtered.StateResult != contract.ReaderSuccess || filtered.Payload == nil || json.Unmarshal(filtered.Artifact, &doc) != nil || doc.Provider == nil || *doc.Provider != provider || doc.Selection != (manifestsdk.Selection{TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.AllAuthorized}) || len(doc.Entries) != 4 || len(doc.Excluded) != 0 {
					t.Fatal("installed provider scope", provider, filtered.StateResult, filtered.FailureReason)
				}
				for i, row := range doc.Entries {
					if row.Name != []string{"", "a/\n雪", "encoded", "secret"}[i] {
						t.Fatal("filtered exact selected set")
					}
					if row.Content.Kind != "secret" {
						continue
					}
					var expected []readerFixtureProfile
					for _, profile := range readerFixtureProfiles(row.Name) {
						if profile.provider == string(provider) {
							expected = append(expected, profile)
						}
					}
					if len(row.Content.Destinations) != len(expected) {
						t.Fatal("complete matching service vector", provider, row.Name)
					}
					for i, d := range row.Content.Destinations {
						var policy bytes.Buffer
						if err := json.Compact(&policy, d.Policy); err != nil {
							t.Fatal("manifest policy is invalid", err)
						}
						if d.ID != expected[i].destination || d.Provider != expected[i].provider || d.Locator != expected[i].locator || policy.String() != readerFixturePolicyJSON(root.Domain, expected[i].policy) {
							t.Fatal("service filter changed exact locator or scope", provider, row.Name)
						}
					}
				}
			}
			defaults := engine.Manifest(ctx, contract.Hash([]byte("default Authority selection")), contract.ManifestRequest{Renderer: manifestTestScope(manifestsdk.Selection{}).Renderer, FormatContractID: genericjson.FormatContractID, ConfigContractID: genericjson.ConfigContractID, Settings: []byte(`{}`), TargetMode: manifestsdk.CurrentAuthority, EntryMode: manifestsdk.AllAuthorized})
			if defaults.StateResult != contract.ReaderSuccess || defaults.TargetRecipientID != basis.AuthorityRecipientID || defaults.Payload == nil || len(defaults.Payload.IncludedEntries) != 4 || len(defaults.Payload.ExcludedEntries) != 0 {
				t.Fatal("installed default target and complete granted set", defaults.StateResult, defaults.FailureReason)
			}
			for _, render := range []func(core.PublicManifestResult) ([]byte, error){RenderManifestResultJSON, RenderManifestResultHuman} {
				body, err := render(manifest)
				if err != nil || bytes.Contains(body, manifest.Artifact) || bytes.Contains(body, []byte("enkv first secret test value")) {
					t.Fatal("manifest result disclosed artifact", err)
				}
			}
			empty := engine.Manifest(ctx, contract.Hash([]byte("empty Reader manifest")), contract.ManifestRequest{Renderer: manifestTestScope(manifestsdk.Selection{}).Renderer, FormatContractID: genericjson.FormatContractID, ConfigContractID: genericjson.ConfigContractID, Settings: []byte(`{}`), TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames, TargetRecipientID: target, EntryNames: []string{}})
			if empty.StateResult != contract.ReaderSuccess || string(empty.Artifact) != readerExpectedManifest(t, head, root, target, entries, bindings, true) {
				t.Fatal("explicit empty manifest failed")
			}
			var unauthorized contract.ID
			for _, recipient := range basis.Recipients {
				if recipient.RecipientID != target && recipient.RecipientID != basis.AuthorityRecipientID {
					unauthorized = recipient.RecipientID
				}
			}
			if unauthorized.IsZero() {
				t.Fatal("fixture lacks unassigned current target")
			}
			noGrants := engine.Manifest(ctx, contract.Hash([]byte("no-grants target")), contract.ManifestRequest{Renderer: manifestTestScope(manifestsdk.Selection{}).Renderer, FormatContractID: genericjson.FormatContractID, ConfigContractID: genericjson.ConfigContractID, Settings: []byte(`{}`), TargetMode: manifestsdk.ExactRecipient, TargetRecipientID: unauthorized, EntryMode: manifestsdk.AllAuthorized})
			if noGrants.StateResult != contract.ReaderSuccess || noGrants.Payload == nil || len(noGrants.Payload.IncludedEntries) != 0 || len(noGrants.Payload.ExcludedEntries) != 0 {
				t.Fatal("current no-grants target", noGrants.StateResult, noGrants.FailureReason)
			}
			for _, test := range []struct {
				request contract.ManifestRequest
				reason  contract.DiagnosticReason
			}{
				{contract.ManifestRequest{Renderer: manifestTestScope(manifestsdk.Selection{}).Renderer, FormatContractID: genericjson.FormatContractID, ConfigContractID: genericjson.ConfigContractID, Settings: []byte(`{}`), TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames, TargetRecipientID: target}, contract.ReasonMissingRequiredField},
				{contract.ManifestRequest{Renderer: manifestTestScope(manifestsdk.Selection{}).Renderer, FormatContractID: genericjson.FormatContractID, ConfigContractID: genericjson.ConfigContractID, Settings: []byte(`{}`), TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames, TargetRecipientID: target, EntryNames: []string{"secret", "secret"}}, contract.ReasonDuplicateEntry},
				{contract.ManifestRequest{Renderer: manifestTestScope(manifestsdk.Selection{}).Renderer, FormatContractID: genericjson.FormatContractID, ConfigContractID: genericjson.ConfigContractID, Settings: []byte(`{}`), TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames, TargetRecipientID: target, EntryNames: []string{"missing"}}, contract.ReasonEntryAbsent},
				{contract.ManifestRequest{Renderer: manifestTestScope(manifestsdk.Selection{}).Renderer, FormatContractID: genericjson.FormatContractID, ConfigContractID: genericjson.ConfigContractID, Settings: []byte(`{}`), TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames, TargetRecipientID: contract.Hash([]byte("absent target")), EntryNames: []string{}}, contract.ReasonTargetAbsent},
				{contract.ManifestRequest{Renderer: manifestTestScope(manifestsdk.Selection{}).Renderer, FormatContractID: genericjson.FormatContractID, ConfigContractID: genericjson.ConfigContractID, Settings: []byte(`{}`), TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames, TargetRecipientID: unauthorized, EntryNames: []string{"", "secret"}}, contract.ReasonTargetNotAuthorized},
			} {
				failed := engine.Manifest(ctx, contract.Hash([]byte("invalid manifest selection")), test.request)
				if failed.StateResult != contract.ReaderRefused || failed.FailureReason != test.reason || failed.Payload != nil || failed.Artifact != nil {
					t.Fatal("failed selection returned wrong failure or artifact", failed.FailureReason, test.reason)
				}
			}
			changed := readerFixtureInput(basis, a.Family)
			changed.Entries.Value[1].PlainValue.Value = []byte{0, 10, 66}
			changed.Recipients.Value[0].Encryption.PublicKey = contract.PublicField[[]byte]{State: contract.PublicUnavailable}
			partial := ConfigurationComparisonResult{PublicComparisonResult: engine.Compare(ctx, contract.Hash([]byte("field partial comparison")), changed), InstallationRequirements: InstallationRequirementComparison{Differences: []InstallationRequirementDifference{}}}
			changes := []contract.ComparisonChange{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: "a/\n雪"}, Path: []contract.DiagnosticField{contract.FieldPlainValue}, Action: contract.ComparisonChanged, Before: proposedSide(contract.ComparisonBytes{0, 10, 65}), After: proposedSide(contract.ComparisonBytes{0, 10, 66})}}
			expected := []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectRecipient, RecipientID: changed.Recipients.Value[0].RecipientID}, Path: []contract.DiagnosticField{contract.FieldEncryptionPublicKey}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonPublicFactUnavailable}}
			if partial.StateResult != contract.ReaderUnavailable || partial.Verdict != contract.ComparisonUnable || !partial.DiagnosticsComplete || !reflect.DeepEqual(partial.Diagnostics, expected) || !reflect.DeepEqual(partial.Changes, changes) || ComparisonExitCode(partial) != 3 {
				t.Fatal("independent difference/failure lost", partial)
			}
			assertReaderRenderings(t, partial)

			h.reset(true, "", 0)
			invalid := readerFixtureInput(basis, a.Family)
			invalid.Entries.Value = append(invalid.Entries.Value, invalid.Entries.Value[0])
			invalid.Entries.Value[0].PlainValue.Value = []byte("secret-sentinel")
			recorder := telemetry.NewRecorder()
			telemetryCtx := telemetry.WithCapability(ctx, telemetry.NewCapability(nil, recorder))
			unavailable := ConfigurationComparisonResult{PublicComparisonResult: engine.Compare(telemetryCtx, contract.Hash([]byte("source and read failure")), invalid), InstallationRequirements: InstallationRequirementComparison{Differences: []InstallationRequirementDifference{}}}
			expected = []contract.Diagnostic{{Subject: contract.DiagnosticSubject{Kind: contract.SubjectEntry, Name: ""}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonDuplicateKey}, {Subject: contract.DiagnosticSubject{Kind: contract.SubjectObservation}, Path: []contract.DiagnosticField{contract.FieldPresence}, Outcome: contract.DiagnosticUnable, Reason: contract.ReasonEvidenceUnavailable}}
			if unavailable.StateResult != contract.ReaderRefused || unavailable.Verdict != contract.ComparisonUnable || unavailable.Observation != nil || !reflect.DeepEqual(unavailable.Diagnostics, expected) || ComparisonExitCode(unavailable) != 2 || h.count("fixture/HEAD") != 1 {
				t.Fatal("fault precedence or implicit retry", unavailable)
			}
			assertReaderRenderings(t, unavailable)
			records := recorder.Drain(make([]telemetry.DiagnosticRecord, 0, 256))
			for _, record := range records {
				body, err := json.Marshal(record)
				if err != nil || record.Validate() != nil || bytes.Contains(body, []byte("secret-sentinel")) || bytes.Contains(body, []byte("raw-error-sentinel")) {
					t.Fatal("provider/source input leaked in telemetry")
				}
			}

			h.reset(false, outputKey, finalOutputRead)
			lateDesired := readerFixtureInput(basis, a.Family)
			lateDesired.Entries.Value[1].PlainValue.Value = []byte{0, 10, 66}
			late := ConfigurationComparisonResult{PublicComparisonResult: engine.Compare(ctx, contract.Hash([]byte("late public proof failure")), lateDesired), InstallationRequirements: InstallationRequirementComparison{Differences: []InstallationRequirementDifference{}}}
			if h.count(outputKey) != finalOutputRead || late.Verdict != contract.ComparisonUnable || late.StateResult != contract.ReaderPositiveDefect || late.Observation == nil || len(late.Diagnostics) != 1 || late.Diagnostics[0].Subject.Kind != contract.SubjectObservation || late.Diagnostics[0].Reason != contract.ReasonSelectedObjectInvalid || ComparisonExitCode(late) != 2 {
				t.Fatal("late shared failure left trusted differences", late)
			}
			assertReaderRenderings(t, late)
			canceled, end := context.WithCancel(ctx)
			end()
			refused := engine.Manifest(canceled, contract.Hash([]byte("cancelled manifest")), contract.ManifestRequest{Renderer: manifestTestScope(manifestsdk.Selection{}).Renderer, FormatContractID: genericjson.FormatContractID, ConfigContractID: genericjson.ConfigContractID, Settings: []byte(`{}`), TargetMode: manifestsdk.ExactRecipient, EntryMode: manifestsdk.ExactNames, TargetRecipientID: target, EntryNames: []string{}})
			if refused.StateResult != contract.ReaderRefused || refused.FailureReason != contract.ReasonCancelled || refused.Artifact != nil {
				t.Fatal("cancelled manifest returned bytes")
			}
			engine.Close()
			stop()
			h.assertNoEffects(t)
			// Independently consume the completed backing after its Reader and server close.
			var consumed map[string]json.RawMessage
			if json.Unmarshal(manifest.Artifact, &consumed) != nil || len(consumed) != 10 || string(manifest.Artifact) != want {
				t.Fatal("completed artifact lost its caller-owned lifetime")
			}
		})
	}
}

func assertReaderDiagnosticRecord(t *testing.T, body []byte, want contract.Diagnostic) {
	t.Helper()
	var wire struct {
		Subject struct {
			Kind          contract.DiagnosticSubjectKind `json:"kind"`
			Name          *string                        `json:"name"`
			RecipientID   string                         `json:"recipient_id"`
			DestinationID string                         `json:"destination_id"`
			Recipient     *struct {
				Kind string `json:"kind"`
				ID   string `json:"recipient_id"`
			} `json:"recipient"`
			Entry *struct {
				Kind string `json:"kind"`
				Name string `json:"name"`
			} `json:"entry"`
		} `json:"subject"`
		Path []struct {
			Field contract.DiagnosticField `json:"field"`
		} `json:"path"`
		Outcome contract.DiagnosticOutcome `json:"outcome"`
		Reason  contract.DiagnosticReason  `json:"reason"`
		Source  *struct {
			ID     string `json:"source_id"`
			Line   uint64 `json:"line"`
			Column uint64 `json:"column"`
		} `json:"source_location"`
	}
	if json.Unmarshal(body, &wire) != nil {
		t.Fatal("diagnostic is not usable JSON")
	}
	parseID := func(text string) contract.ID {
		var id contract.ID
		if text == "" {
			return id
		}
		decoded, err := hex.DecodeString(text)
		if err != nil || len(decoded) != 32 || text != hex.EncodeToString(decoded) {
			t.Fatal("diagnostic identity is not exact")
		}
		copy(id[:], decoded)
		return id
	}
	got := contract.Diagnostic{Subject: contract.DiagnosticSubject{Kind: wire.Subject.Kind, RecipientID: parseID(wire.Subject.RecipientID), DestinationID: wire.Subject.DestinationID}, Outcome: wire.Outcome, Reason: wire.Reason}
	if wire.Subject.Name != nil {
		got.Subject.Name = *wire.Subject.Name
	}
	if wire.Subject.Kind == contract.SubjectEntry || wire.Subject.Kind == contract.SubjectOutputTarget {
		if wire.Subject.Name == nil {
			t.Fatal("diagnostic lost explicit empty name")
		}
	}
	if wire.Subject.Recipient != nil {
		t.Fatal("diagnostic retained a recipient-specific routing field")
	}
	if wire.Subject.Entry != nil {
		switch wire.Subject.Entry.Kind {
		case "default":
			got.Subject.RoutingKey.EntrySelector = contract.PublicDefaultRoute
		case "entry":
			got.Subject.RoutingKey.EntrySelector = contract.PublicNamedEntry
			got.Subject.RoutingKey.EntryName = wire.Subject.Entry.Name
		default:
			t.Fatal("diagnostic lost routing entry tag")
		}
	}
	for _, field := range wire.Path {
		got.Path = append(got.Path, field.Field)
	}
	if wire.Source != nil {
		got.SourceLocation = &contract.SourceLocation{SourceID: wire.Source.ID, Line: wire.Source.Line, Column: wire.Source.Column}
	}
	if want.Subject.Kind == contract.SubjectRecipient && want.Subject.RecipientID.IsZero() {
		presence := len(want.Path) == 1 && want.Path[0] == contract.FieldPresence
		if presence && wire.Subject.RecipientID != "" || !presence && wire.Subject.RecipientID != strings.Repeat("0", 64) {
			t.Fatal("malformed source ID became a fabricated section/item identity")
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("diagnostic wire changed actual Core fact", got, want)
	}
}
