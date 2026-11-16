package installedarchive

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"testing"
)

const (
	MaximumCloudflareIntentBytes = 393216
	MaximumCloudflareAccount     = "0123456789abcdef0123456789abcdef"
	MaximumCloudflareOrigin      = "https://127.0.0.1:1/client/v4"
	MaximumCloudflareSecret      = "Generated_secret_0123456789_ABCDEFGHIJKLMN"
)

// This canonical JSON reaches the common complete-intent ceiling. It keeps all
// 32 policies, all 64 permissions per policy, both 128-row IPv6 lists and both
// timestamps. Resources total 5,618: 256 in the first policy, 173 in each next
// 30 policies and 172 in the last. The 89-byte name makes the exact byte limit.
// The private provider-controls test owns the old simultaneous count maxima,
// whose 537,320-byte canonical settings exceed the common settings ceiling.
func MaximumCloudflareIntent(t testing.TB, name string) ([]byte, []byte) {
	t.Helper()
	if len(name) != 89 {
		t.Fatal("maximum canonical provider name must have 89 bytes")
	}
	type resource struct {
		Kind string `json:"kind"`
		ID   string `json:"id"`
	}
	type policy struct {
		Effect      string     `json:"effect"`
		Permissions []string   `json:"permission_groups"`
		Resources   []resource `json:"resources"`
	}
	type ipLists struct {
		In    []string `json:"in"`
		NotIn []string `json:"not_in"`
	}
	type settings struct {
		Account   string   `json:"account"`
		Name      string   `json:"name"`
		Policies  []policy `json:"policies"`
		IP        ipLists  `json:"request_ip"`
		NotBefore string   `json:"not_before"`
		ExpiresOn string   `json:"expires_on"`
	}
	input := settings{Account: MaximumCloudflareAccount, Name: name, Policies: make([]policy, 32), NotBefore: "2030-01-01T00:00:00Z", ExpiresOn: "2040-01-01T00:00:00Z"}
	providerPolicies := make([]json.RawMessage, 32)
	resourcesTotal := 0
	for p := range input.Policies {
		count := 173
		if p == 0 {
			count = 256
		}
		if p == 31 {
			count = 172
		}
		resourcesTotal += count
		row := policy{Effect: "allow", Permissions: make([]string, 64), Resources: make([]resource, count)}
		permissions := make([]map[string]string, 64)
		resources := make(map[string]string, count)
		for i := range row.Permissions {
			tag := fmt.Sprintf("%032x", p*64+i+1)
			row.Permissions[i] = tag
			permissions[i] = map[string]string{"id": tag}
		}
		for i := range row.Resources {
			tag := fmt.Sprintf("%032x", i+1)
			row.Resources[i] = resource{Kind: "zone", ID: tag}
			resources["com.cloudflare.api.account.zone."+tag] = "*"
		}
		input.Policies[p] = row
		encoded, err := json.Marshal(struct {
			Effect      string              `json:"effect"`
			Permissions []map[string]string `json:"permission_groups"`
			Resources   map[string]string   `json:"resources"`
		}{"allow", permissions, resources})
		if err != nil {
			t.Fatal(err)
		}
		providerPolicies[p] = encoded
	}
	for list, destination := range []*[]string{&input.IP.In, &input.IP.NotIn} {
		*destination = make([]string, 128)
		for i := range *destination {
			prefix := netip.MustParsePrefix(fmt.Sprintf("2001:db%x::%x/128", 8+list, i+1))
			(*destination)[i] = prefix.String()
		}
	}
	canonical, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	// Independent account: old full shape537320 minus2574 resource rows*56,
	// minus31 name bytes gives393145 settings; generic framing adds71 bytes.
	const canonicalBytes = 537320 - 2574*56 - 31
	if resourcesTotal != 5618 || len(canonical) != canonicalBytes || canonicalBytes+71 != MaximumCloudflareIntentBytes {
		t.Fatal("independent maximum canonical byte account differs", len(canonical), resourcesTotal)
	}
	config := sha256.Sum256([]byte("ENKV/CLOUDFLARE-ACCOUNT-TOKEN/CONFIG/v1\x00https://api.cloudflare.com/client/v4"))
	resourceID := sha256.Sum256([]byte("ENKV/CLOUDFLARE-ACCOUNT-TOKEN/RESOURCE/v1\x00https://api.cloudflare.com/client/v4"))
	body := []byte{0, 1}
	body = append(body, config[:]...)
	body = append(body, 2)
	body = append(body, resourceID[:]...)
	body = binary.BigEndian.AppendUint32(body, uint32(len(canonical)))
	body = append(body, canonical...)
	request, err := json.Marshal(struct {
		Name      string             `json:"name"`
		Policies  []json.RawMessage  `json:"policies"`
		Condition map[string]ipLists `json:"condition"`
		NotBefore string             `json:"not_before"`
		ExpiresOn string             `json:"expires_on"`
	}{name, providerPolicies, map[string]ipLists{"request.ip": input.IP}, input.NotBefore, input.ExpiresOn})
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != MaximumCloudflareIntentBytes || len(request) > 1<<20 || !json.Valid(request) {
		t.Fatal("maximum intent or provider request bound differs")
	}
	return body, request
}
