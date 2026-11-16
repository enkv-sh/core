package custody

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"

	"enkv.sh/core/contract"
)

// Fixed answers were calculated once with explicit field arithmetic and
// Node/OpenSSL SHA-256, HKDF, HMAC and AES-256-GCM. No production encoder,
// key derivation or sealing function supplied expected bytes. B(x) is
// u32be(len(x)) || x; L(s) is ENKV/CRYPTO/v2/ || s || NUL.
// Canonical material/value contexts use schema11; result core uses schema4. Generator
// identity labels stay v1; crypto labels and transfer schema stay v2.
// The existing generatedResultContext fixture supplies public IDs. The seed
// repeats 0x80; D/C are 0x00..0x3f. Result and transfer nonces are 0x00..0x0b
// and 0x0c..0x17. All private inputs are synthetic and stay local.
const generatedVectorUseDigest = "f804b4935ce9003846b9759a9da7648d052a3ac8f60c119a3ec26cbcce2b9fd1"
const generatedVectorSeedCheck = "7e0f8dc9f17c093d06b3d9d16be98da56a93895df5e3281d4033645b2ef58731"

const generatedVectorUsePlanHex = "030303030303030303030303030303030303030303030303030303030303030311111111111111111111111111111111111111111111111111111111111111119cfff55b87a515ef80a20bcb0f744d7970b0220cc8d801baa9ee8037f41f1f590d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d7642e544c02a1113dfaeb608bfdc639b31dead6deeae963b5046a9cb8a84886600000000000000f300000001f61ee14eaadd5ebda3f390acc185ca0301f11a811fae92bd26f2bd03364130e60000000000000004000000003d885a7db1b3a14bd0000c331f3d3fe0ff200d93bb0c6cf270eadbfbd4501503"

const generatedVectorMaterialHex = "000b000201010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202030303030303030303030303030303030303030303030303030303030303030311111111111111111111111111111111111111111111111111111111111111119cfff55b87a515ef80a20bcb0f744d7970b0220cc8d801baa9ee8037f41f1f59f804b4935ce9003846b9759a9da7648d052a3ac8f60c119a3ec26cbcce2b9fd10000000000000001"

const generatedVectorResultCoreHex = "00040002030303030303030303030303030303030303030303030303030303030303030311111111111111111111111111111111111111111111111111111111111111119cfff55b87a515ef80a20bcb0f744d7970b0220cc8d801baa9ee8037f41f1f59f804b4935ce9003846b9759a9da7648d052a3ac8f60c119a3ec26cbcce2b9fd10d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d59b11139a2821fcaea11d89fc14e8f2b77bf9fcb32e35c348088a908affb29d20ec32ee614dd02984572c1041cf1181ac048313c72b44447b043d25d347e9e9c95da8aecb5b94c9fb04d8361a28e8346423a9d4df6e063a6757cadce7a1fc94a0707070707070707070707070707070707070707070707070707070707070707050505050505050505050505050505050505050505050505050505050505050506060606060606060606060606060606060606060606060606060606060606060a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e87812550c39727c0d7a65bf84db219b01dac948a7f12c3daf250068f48792ce6"

const generatedVectorRecordHex = "000001c400040002030303030303030303030303030303030303030303030303030303030303030311111111111111111111111111111111111111111111111111111111111111119cfff55b87a515ef80a20bcb0f744d7970b0220cc8d801baa9ee8037f41f1f59f804b4935ce9003846b9759a9da7648d052a3ac8f60c119a3ec26cbcce2b9fd10d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d59b11139a2821fcaea11d89fc14e8f2b77bf9fcb32e35c348088a908affb29d20ec32ee614dd02984572c1041cf1181ac048313c72b44447b043d25d347e9e9c95da8aecb5b94c9fb04d8361a28e8346423a9d4df6e063a6757cadce7a1fc94a0707070707070707070707070707070707070707070707070707070707070707050505050505050505050505050505050505050505050505050505050505050506060606060606060606060606060606060606060606060606060606060606060a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e87812550c39727c0d7a65bf84db219b01dac948a7f12c3daf250068f48792ce6000000b60004010201000e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0909090909090909090909090909090909090909090909090909090909090909000000200c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c000000200f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f00000003c8010300000000e3000202020202020202020202020202020202020202020202020202020202020202025bcca0963cb36e3c49bba10cb4dfa8f07601f352f8944ef37922b35478ca82ab000000000000000112b1be946a0d640d148c0e027c91afbe2332ea22ef71def593548063b8204db600000000000000010000000c010000000c000102030405060708090a0b1cd9ea7a0e8a8768249d927cca88ef1683a0277d406675a0d0666a22030d983760cc89876722c4bca47525db6bf9a31bbaa839daacf20fc2d73a6c207c6e040e3467b569a091ef6dec2de2ee337b2660aa668310104341fbec969a30000001da454e4b562f5452414e534645522f7632000002000201010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202030303030303030303030303030303030303030303030303030303030303030311111111111111111111111111111111111111111111111111111111111111119cfff55b87a515ef80a20bcb0f744d7970b0220cc8d801baa9ee8037f41f1f59f804b4935ce9003846b9759a9da7648d052a3ac8f60c119a3ec26cbcce2b9fd11818181818181818181818181818181818181818181818181818181818181818020006006459b11139a2821fcaea11d89fc14e8f2b77bf9fcb32e35c348088a908affb29d295da8aecb5b94c9fb04d8361a28e8346423a9d4df6e063a6757cadce7a1fc94aa88076713dc1628835896bce49a9e598682e4398de3aa4c187892e36be3de4750c0d0e0f10111213141516176b30ef5ff122f5f7b8d6472304cd1eafffbd5289226d864819a180591c78ec2ee6cb6a190a665f855c4d639f9dc129192bb0149212cd4c7d60320ab14af2ac805b504a23e5ebb21608679c1056127e85ae53f862f38a2a35ee7ba80ee60456dc2a1b7d1f696f18697372852a6730a8141b650bc9"

const generatedVectorSourceTransferHex = "454e4b562f5452414e534645522f7632000002000201010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202030303030303030303030303030303030303030303030303030303030303030311111111111111111111111111111111111111111111111111111111111111119cfff55b87a515ef80a20bcb0f744d7970b0220cc8d801baa9ee8037f41f1f59f804b4935ce9003846b9759a9da7648d052a3ac8f60c119a3ec26cbcce2b9fd1191919191919191919191919191919191919191919191919191919191919191901000500440c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a0c0d0e0f101112131415161774e43bbbd2cba1d4f582ab28539d53fcc4b9c9db94aca1cb0af4d31a04427138fc10966c8c6de78eab336dd9ec005151dae3b08cc20344fb4bd654f0602e449de0eb79f5b8f36c411db8bc0669a3c6e507ddfd82"

func generatedVectorID(t testing.TB, literal string) contract.ID {
	t.Helper()
	b := hexBytes(t, literal)
	if len(b) != 32 {
		t.Fatal("invalid fixed ID length")
	}
	return contract.ID(b)
}

func generatedVectorFixture(t testing.TB) (contract.GeneratorResultExpectation, contract.OperationMaterialRecord, contract.GeneratedResultRecord, []byte) {
	t.Helper()
	expected, material, _, seed := generatedResultContext(t, 1)
	if material.Core.UsePlanDigest != generatedVectorID(t, generatedVectorUseDigest) ||
		material.SeedCheck != generatedVectorID(t, generatedVectorSeedCheck) {
		clear(seed)
		t.Fatal("fixture differs from independent use-plan or seed check")
	}
	wire := hexBytes(t, generatedVectorRecordHex)
	record, err := contract.DecodeGeneratedResultRecord(wire)
	if err != nil {
		clear(seed)
		t.Fatal("independent generated result refused")
	}
	clear(wire)
	return expected, material, record, seed
}

// full_only: false
func TestGeneratedVectorSeedCheckAndContext(t *testing.T) {
	expected, material, _, seed := generatedVectorFixture(t)
	defer clear(seed[:cap(seed)])
	for _, row := range []struct {
		name, literal string
		encode        func() ([]byte, error)
	}{
		{"use plan", generatedVectorUsePlanHex, func() ([]byte, error) { return contract.EncodeGeneratorUsePlanCore(expected.Plan) }},
		{"material", generatedVectorMaterialHex, func() ([]byte, error) { return contract.EncodeOperationMaterialCore(material.Core) }},
	} {
		actual, err := row.encode()
		if err != nil || !bytes.Equal(actual, hexBytes(t, row.literal)) {
			t.Fatalf("%s differs from independent fields", row.name)
		}
	}
	check, err := SeedCheck(material.Core, seed)
	if err != nil || check != generatedVectorID(t, generatedVectorSeedCheck) {
		t.Fatal("seed check differs from independent HKDF/HMAC")
	}
	context, err := contract.OperationMaterialContextDigest(material.Core)
	if err != nil || context != generatedVectorID(t, "7740537075c7118f2139c2ce5050061b2e1483b60d88f88aac2bc4f1b756ff92") {
		t.Fatal("seed context differs from independent SHA-256")
	}
	immutable, err := contract.OperationImmutableBodyDigest(material.Core, check)
	if err != nil || immutable != generatedVectorID(t, "75afccb6df83c2a50d4ea9bfa0343544b13d63a17f08832485545d5e72caddd3") {
		t.Fatal("immutable kind-3 seed body differs from independent digest")
	}
	_, recipient := wrappingKey(t)
	wrap, err := SeedWrapCore(material.Core, recipient)
	if err != nil || wrap.MaterialKind != 3 || wrap.PacketKind != 3 || wrap.PacketLength != 68 || wrap.MaterialContextDigest != context {
		t.Fatal("seed wrap omitted its kind-3 context")
	}
	packet, err := EncodePacket(3, independentPacketContext(wrap), seed)
	if err != nil || len(packet) != 68 || !bytes.Equal(packet[36:], seed) {
		t.Fatal("seed packet has the wrong body")
	}
	clear(packet[:cap(packet)])
	for _, row := range []struct {
		name   string
		change func(*contract.OperationMaterialCore)
	}{
		{"compatibility", func(c *contract.OperationMaterialCore) { c.CompatibilityID[0] ^= 1 }},
		{"support", func(c *contract.OperationMaterialCore) { c.CryptoSupportID[0] ^= 1 }},
		{"domain", func(c *contract.OperationMaterialCore) { c.DomainID[0] ^= 1 }},
		{"operation", func(c *contract.OperationMaterialCore) { c.OperationID[0] ^= 1 }},
		{"material", func(c *contract.OperationMaterialCore) { c.OperationMaterialID[0] ^= 1 }},
		{"use plan", func(c *contract.OperationMaterialCore) { c.UsePlanDigest[0] ^= 1 }},
		{"epoch", func(c *contract.OperationMaterialCore) { c.SeedEpoch++ }},
	} {
		t.Run(row.name, func(t *testing.T) {
			core := material.Core
			row.change(&core)
			if changed, err := SeedCheck(core, seed); err != nil || changed == check {
				t.Fatal("seed check omitted changed context")
			}
		})
	}
	for _, n := range []int{0, 31, 33} {
		if _, err := SeedCheck(material.Core, make([]byte, n)); err == nil {
			t.Fatal("invalid seed length accepted")
		}
	}
	material.Core.SeedEpoch = 0
	if _, err := SeedCheck(material.Core, seed); err == nil {
		t.Fatal("zero seed epoch accepted")
	}
}

// full_only: false
func TestGeneratedVectorResultAndTransferKnownAnswers(t *testing.T) {
	expected, material, record, seed := generatedVectorFixture(t)
	keys := fixtureKeys()
	defer clear(seed[:cap(seed)])
	defer clear(keys[:cap(keys)])
	core, err := contract.ExpectedGeneratedResultCore(expected, material, record.SafeFacts)
	if err != nil || core != record.Core {
		t.Fatal("result context differs from independent core")
	}
	body, err := contract.EncodeGeneratedResultCore(core)
	if err != nil || !bytes.Equal(body, hexBytes(t, generatedVectorResultCoreHex)) ||
		sha256.Sum256(body) != generatedVectorID(t, "a88076713dc1628835896bce49a9e598682e4398de3aa4c187892e36be3de475") {
		t.Fatal("result core differs from independent bytes or digest")
	}
	data, commitment, err := contract.GeneratorResultKeyIDs(core.ResultID)
	if err != nil || data != generatedVectorID(t, "5bcca0963cb36e3c49bba10cb4dfa8f07601f352f8944ef37922b35478ca82ab") ||
		commitment != generatedVectorID(t, "12b1be946a0d640d148c0e027c91afbe2332ea22ef71def593548063b8204db6") ||
		record.Payload.DataKeyID != data || record.Payload.CommitmentKeyID != commitment {
		t.Fatal("result payload did not use result-only key identities")
	}
	check, err := retainedCheck(body, keys, "result-package-hkdf-salt", "result-package-hkdf-info", "result-package-check")
	if err != nil || check != generatedVectorID(t, "60cc89876722c4bca47525db6bf9a31bbaa839daacf20fc2d73a6c207c6e040e") || check != record.Payload.PackageCheck {
		t.Fatal("result package check differs from independent HKDF/HMAC")
	}
	if resultSemantic(body, []byte("secret-value"), keys[32:]) != generatedVectorID(t, "1cd9ea7a0e8a8768249d927cca88ef1683a0277d406675a0d0666a22030d9837") {
		t.Fatal("result semantic commitment differs from independent HMAC")
	}
	key, _, err := transferKey(record.Transfer.Core, seed)
	wantKey := hexBytes(t, "38288cf8f3f7b9afa2d82af58160d3644825d9c3bfd4286bb0aa538aef21ebbc")
	defer clear(wantKey[:cap(wantKey)])
	if err != nil || !bytes.Equal(key, wantKey) {
		clear(key)
		t.Fatal("transfer key differs from independent HKDF")
	}
	clear(key[:cap(key)])
	context, err := contract.TransferPacketContextDigest(record.Transfer.Core)
	if err != nil || context != generatedVectorID(t, "9ce1398cf6b082aa70d5909cda1d1e74d19ace9dbc010fef6dfe69eabba383ae") {
		t.Fatal("transfer packet context differs from independent SHA-256")
	}
	openedKeys, err := OpenTransfer(record.Transfer.Core, record.Transfer, seed)
	if err != nil || !bytes.Equal(openedKeys, keys) || len(openedKeys) != 64 || cap(openedKeys) != 64 {
		clear(openedKeys)
		t.Fatal("independent transfer did not return one owned key pair")
	}
	clear(openedKeys[:cap(openedKeys)])
	got, err := OpenGeneratedResult(expected, material, seed, record)
	if err != nil || !bytes.Equal(got, []byte("secret-value")) || cap(got) != 12 {
		clear(got)
		t.Fatal("independent generated result did not open")
	}
	clear(got[:cap(got)])
	wire, err := contract.EncodeGeneratedResultRecord(record)
	if err != nil || len(wire) != 1351 || !bytes.Equal(wire, hexBytes(t, generatedVectorRecordHex)) ||
		sha256.Sum256(wire) != generatedVectorID(t, "702ddd4bc0ca57a8cb4c90d78740ad324303aeb1e5d853b1e39cf59883a56290") {
		t.Fatal("owned result changed the fixed complete record")
	}
	// Match all public entry key fields so the refusal depends on purpose.
	valueCore := fixtureValueCore()
	valueCore.DataKeyID, valueCore.CommitmentKeyID = data, commitment
	valueCore.DataKeyEpoch, valueCore.CommitmentKeyEpoch = 1, 1
	if got, err := OpenValue(valueCore, record.Payload, keys); err == nil || got != nil {
		clear(got)
		t.Fatal("result-only payload was accepted as a member")
	}
	// Hold core, key and nonce fixed to isolate the AEAD purpose itself.
	if got, err := openPayload(keys[:32], record.Payload.Nonce, record.Payload.Ciphertext,
		valuePreimage(valueAADLabel, body)); err == nil || got != nil {
		clear(got)
		t.Fatal("result ciphertext opened under member-purpose AAD")
	}
	wrongPurpose := record
	wrongPurpose.Payload.Ciphertext = hexBytes(t, "3467b569a091ef6dec2de2ee29376dcdf168da2fa8d5ad81d2d0c4ac")
	if got, err := OpenGeneratedResult(expected, material, seed, wrongPurpose); err == nil || got != nil {
		clear(got)
		t.Fatal("member-purpose ciphertext was accepted as a result")
	}
	changed := bytes.Clone(body)
	changed[4] ^= 1
	if got, err := openPayload(keys[:32], record.Payload.Nonce, record.Payload.Ciphertext,
		valuePreimage("ENKV/CRYPTO/v2/result-aad\x00", changed)); err == nil || got != nil {
		clear(got)
		t.Fatal("result ciphertext opened under another result context")
	}
}

// full_only: false
func TestGeneratedVectorTransferRefusesContextAndDamage(t *testing.T) {
	for _, mode := range []string{"compatibility", "support", "domain", "operation", "material", "use plan", "attempt", "result", "result core",
		"envelope", "nonce", "ciphertext", "tag", "short", "long", "seed", "seed empty", "seed short", "seed long"} {
		t.Run(mode, func(t *testing.T) {
			_, _, record, seed := generatedVectorFixture(t)
			defer clear(seed[:cap(seed)])
			envelope, expected := record.Transfer, record.Transfer.Core
			switch mode {
			case "compatibility":
				expected.CompatibilityID[0] ^= 1
			case "support":
				expected.CryptoSupportID[0] ^= 1
			case "domain":
				expected.DomainID[0] ^= 1
			case "operation":
				expected.OperationID[0] ^= 1
			case "material":
				expected.OperationMaterialID[0] ^= 1
			case "use plan":
				expected.UsePlanDigest[0] ^= 1
			case "attempt":
				expected.AttemptID[0] ^= 1
			case "result":
				expected.ResultID[0] ^= 1
			case "result core":
				expected.ResultCoreDigest[0] ^= 1
			case "envelope":
				envelope.Core.EnvelopeID[0] ^= 1
			case "nonce":
				envelope.Nonce[0] ^= 1
			case "ciphertext":
				envelope.Ciphertext[0] ^= 1
			case "tag":
				envelope.Ciphertext[len(envelope.Ciphertext)-1] ^= 1
			case "short":
				envelope.Ciphertext = envelope.Ciphertext[:len(envelope.Ciphertext)-1]
			case "long":
				envelope.Ciphertext = append(envelope.Ciphertext, 0)
			case "seed":
				seed[0] ^= 1
			case "seed empty":
				seed = seed[:0]
			case "seed short":
				seed = seed[:31]
			case "seed long":
				seed = append(seed, 0)
			}
			defer clear(seed[:cap(seed)])
			before, seedBefore := bytes.Clone(envelope.Ciphertext), bytes.Clone(seed)
			defer clear(seedBefore[:cap(seedBefore)])
			got, err := OpenTransfer(expected, envelope, seed)
			if err == nil || got != nil || !bytes.Equal(before, envelope.Ciphertext) || !bytes.Equal(seedBefore, seed) {
				clear(got)
				t.Fatal("refused transfer released keys or changed borrowed input")
			}
		})
	}
}

// full_only: false
func TestGeneratedVectorAuthenticatedWrongPrivatePackets(t *testing.T) {
	// Each fixed ciphertext has a valid GCM tag for the unchanged transfer
	// core, but its decrypted packet has one invalid version, kind or context.
	for _, row := range []struct{ name, ciphertext string }{
		{"version", "6a30ef5ff122f5f7b8d6472304cd1eafffbd5289226d864819a180591c78ec2ee6cb6a190a665f855c4d639f9dc129192bb0149212cd4c7d60320ab14af2ac805b504a23e5ebb21608679c1056127e85ae53f862f38a2a35ee7ba80ee60456dc2a1b7d1f068cd1a9bfca6448de66a1c6767cf212"},
		{"purpose", "6b30ee5ff122f5f7b8d6472304cd1eafffbd5289226d864819a180591c78ec2ee6cb6a190a665f855c4d639f9dc129192bb0149212cd4c7d60320ab14af2ac805b504a23e5ebb21608679c1056127e85ae53f862f38a2a35ee7ba80ee60456dc2a1b7d1fd3dc818abab249928652114212b766d0"},
		{"context", "6b30ef5ff022f5f7b8d6472304cd1eafffbd5289226d864819a180591c78ec2ee6cb6a190a665f855c4d639f9dc129192bb0149212cd4c7d60320ab14af2ac805b504a23e5ebb21608679c1056127e85ae53f862f38a2a35ee7ba80ee60456dc2a1b7d1f296650daea914ceaab884976a233021b"},
	} {
		t.Run(row.name, func(t *testing.T) {
			_, _, record, seed := generatedVectorFixture(t)
			defer clear(seed[:cap(seed)])
			envelope := record.Transfer
			envelope.Ciphertext = hexBytes(t, row.ciphertext)
			key, aad, err := transferKey(envelope.Core, seed)
			if err != nil {
				t.Fatal("fixed transfer key refused")
			}
			packet, err := openPayload(key, envelope.Nonce, envelope.Ciphertext, aad)
			clear(key[:cap(key)])
			if err != nil || len(packet) != 100 {
				clear(packet)
				t.Fatal("damaged-packet vector did not authenticate")
			}
			clear(packet[:cap(packet)])
			before := bytes.Clone(envelope.Ciphertext)
			if got, err := OpenTransfer(envelope.Core, envelope, seed); err == nil || got != nil || !bytes.Equal(before, envelope.Ciphertext) {
				clear(got)
				t.Fatal("authenticated wrong private packet released keys")
			}
		})
	}
}

// full_only: false
func TestGeneratedVectorResultRefusalPreservesPrivateInputs(t *testing.T) {
	for _, mode := range []string{"seed check", "package", "semantic", "nonce", "ciphertext", "tag", "raw length", "data epoch", "commitment epoch",
		"data ID", "commitment ID", "attempt", "transmission", "result", "producer", "profile", "assumption", "request", "graph", "facts",
		"planned slot", "inbox", "result use", "transfer"} {
		t.Run(mode, func(t *testing.T) {
			expected, material, record, seed := generatedVectorFixture(t)
			defer clear(seed[:cap(seed)])
			switch mode {
			case "seed check":
				material.SeedCheck[0] ^= 1
			case "package":
				record.Payload.PackageCheck[0] ^= 1
			case "semantic":
				record.Payload.SemanticCommitment[0] ^= 1
			case "nonce":
				record.Payload.Nonce[0] ^= 1
			case "ciphertext":
				record.Payload.Ciphertext[0] ^= 1
			case "tag":
				record.Payload.Ciphertext[len(record.Payload.Ciphertext)-1] ^= 1
			case "raw length":
				record.Payload.ContentLength++
			case "data epoch":
				record.Payload.DataKeyEpoch++
			case "commitment epoch":
				record.Payload.CommitmentKeyEpoch++
			case "data ID":
				record.Payload.DataKeyID[0] ^= 1
			case "commitment ID":
				record.Payload.CommitmentKeyID[0] ^= 1
			case "attempt":
				expected.Template.AttemptID[0] ^= 1
			case "transmission":
				expected.Template.TransmissionID[0] ^= 1
			case "result":
				expected.Template.ResultID[0] ^= 1
			case "producer":
				record.Core.ExecutorID[0] ^= 1
			case "profile":
				record.Core.DescriptorID[0] ^= 1
			case "assumption":
				record.Core.ConfigContractID[0] ^= 1
			case "request":
				expected.RequestDigest[0] ^= 1
			case "graph":
				expected.Plan.PlanGraphID[0] ^= 1
			case "facts":
				record.SafeFacts.ResourceData[0] ^= 1
			case "planned slot":
				expected.Use.PlannedValueSlotID[0] ^= 1
			case "inbox":
				expected.Use.InboxID[0] ^= 1
			case "result use":
				expected.Use.ResultID[0] ^= 1
			case "transfer":
				record.Transfer.Ciphertext[0] ^= 1
			}
			payloadBefore, transferBefore, seedBefore := bytes.Clone(record.Payload.Ciphertext), bytes.Clone(record.Transfer.Ciphertext), bytes.Clone(seed)
			defer clear(seedBefore[:cap(seedBefore)])
			got, err := OpenGeneratedResult(expected, material, seed, record)
			if err == nil || got != nil || !bytes.Equal(payloadBefore, record.Payload.Ciphertext) ||
				!bytes.Equal(transferBefore, record.Transfer.Ciphertext) || !bytes.Equal(seedBefore, seed) {
				clear(got)
				t.Fatal("refused result released plaintext or changed borrowed inputs")
			}
		})
	}
}

// full_only: false
func TestGeneratedVectorTransferPhysicalIdentityAndSourceSeparation(t *testing.T) {
	_, _, record, seed := generatedVectorFixture(t)
	keys := fixtureKeys()
	defer clear(seed[:cap(seed)])
	defer clear(keys[:cap(keys)])
	expected := record.Transfer.Core
	first, err := SealTransfer(expected, seed, keys)
	if err != nil {
		t.Fatal("first physical transfer refused")
	}
	second, err := SealTransfer(expected, seed, keys)
	if err != nil || first.Core.EnvelopeID.IsZero() || second.Core.EnvelopeID.IsZero() || first.Core.EnvelopeID == second.Core.EnvelopeID {
		t.Fatal("physical seals reused an envelope identity")
	}
	for _, envelope := range []contract.TransferEnvelope{first, second} {
		logical := envelope.Core
		logical.EnvelopeID = expected.EnvelopeID
		if logical != expected {
			t.Fatal("physical seal changed logical result context")
		}
		got, err := OpenTransfer(expected, envelope, seed)
		if err != nil || !bytes.Equal(got, keys) {
			clear(got)
			t.Fatal("fresh physical transfer did not open")
		}
		clear(got[:cap(got)])
	}
	frozen, err := contract.EncodeTransferEnvelope(first)
	if err != nil {
		t.Fatal("physical transfer did not encode")
	}
	readback, err := contract.DecodeTransferEnvelope(frozen)
	if err != nil {
		t.Fatal("frozen transfer did not decode")
	}
	retry, err := contract.EncodeTransferEnvelope(readback)
	if err != nil || !bytes.Equal(frozen, retry) {
		t.Fatal("immutable transport retry changed bytes")
	}
	source, err := contract.DecodeTransferEnvelope(hexBytes(t, generatedVectorSourceTransferHex))
	if err != nil {
		t.Fatal("independent source transfer refused")
	}
	got, err := OpenTransfer(source.Core, source, seed)
	if err != nil || !bytes.Equal(got, keys[:32]) || cap(got) != 32 {
		clear(got)
		t.Fatal("source did not return one owned D key")
	}
	clear(got[:cap(got)])
	if got, err := OpenTransfer(expected, source, seed); err == nil || got != nil {
		clear(got)
		t.Fatal("source transfer was accepted as a result transfer")
	}
	if got, err := OpenTransfer(source.Core, record.Transfer, seed); err == nil || got != nil {
		clear(got)
		t.Fatal("result transfer was accepted as a source transfer")
	}
}

// full_only: false
func TestGeneratedVectorSealBoundsAndOwnedOutput(t *testing.T) {
	for _, n := range []int{0, 12, contract.CryptoMaxRawValue} {
		t.Run(fmt.Sprintf("length-%d", n), func(t *testing.T) {
			expected, material, facts, seed := generatedResultContext(t, 1)
			defer clear(seed[:cap(seed)])
			if n == 0 {
				facts.Disposition, facts.Reason = 2, 1
			}
			plain := bytes.Repeat([]byte{0x73}, n)
			defer clear(plain[:cap(plain)])
			record, err := SealGeneratedResult(expected, material, facts, seed, plain)
			if err != nil {
				t.Fatal("bounded generated result did not seal")
			}
			got, err := OpenGeneratedResult(expected, material, seed, record)
			if err != nil || !bytes.Equal(got, plain) || len(got) != n || cap(got) != n {
				clear(got)
				t.Fatal("generated result did not return exact owned plaintext")
			}
			if n != 0 {
				got[0] ^= 1
				if plain[0] != 0x73 {
					clear(got)
					t.Fatal("opened result aliases original plaintext")
				}
			}
			clear(got[:cap(got)])
		})
	}
	for _, mode := range []string{"create empty", "residue nonempty", "unknown", "admitted bound", "global bound"} {
		t.Run(mode, func(t *testing.T) {
			expected, material, facts, seed := generatedResultContext(t, 1)
			defer clear(seed[:cap(seed)])
			plain := []byte("secret-value")
			switch mode {
			case "create empty":
				plain = nil
			case "residue nonempty":
				facts.Disposition, facts.Reason = 2, 1
			case "unknown":
				facts.Disposition, facts.Reason, plain = contract.GeneratorDispositionUnknown, 8, nil
			case "admitted bound":
				expected.Use.MaxSecret = 11
			case "global bound":
				plain = make([]byte, contract.CryptoMaxRawValue+1)
			}
			defer clear(plain[:cap(plain)])
			if _, err := SealGeneratedResult(expected, material, facts, seed, plain); err == nil {
				t.Fatal("invalid result disposition or bound was accepted")
			}
		})
	}
}
