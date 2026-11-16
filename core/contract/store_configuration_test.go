package contract

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// full_only: false
func TestStoreConfigurationIndependentBytes(t *testing.T) {
	var domain ID
	for i := range domain {
		domain[i] = byte(i + 1)
	}
	cases := []struct {
		name, region, bucket, owner, wire, digest string
		provider                                  Family
	}{
		{"aws", "us-east-1", "enkv-example", "123456789012", "454e4b562f53544f52452d434f4e46494755524154494f4e2f7631000100020102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200000000975732d656173742d310000000c656e6b762d6578616d706c65000000097465616d2f70726f640000000c313233343536373839303132", "b701f21d1695852674fa5f8e1ee463db6ae6b91e9d859b3b6aabbda254bb3ebb", AWS},
		{"gcp", "us-central1", "enkv-example-bucket", "", "454e4b562f53544f52452d434f4e46494755524154494f4e2f7631000200020102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f200000000b75732d63656e7472616c3100000013656e6b762d6578616d706c652d6275636b6574000000097465616d2f70726f6400000000", "9be3ffa7419691e01b00331965a7311b2371b072570ed988e1aeb86cac4d220f", GCP},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			configuration := StoreConfiguration{Provider: tt.provider, ConstructionProfile: 2, DomainID: domain, Region: tt.region, Bucket: tt.bucket, PrefixBeforeHEAD: "team/prod", ExpectedOwner: tt.owner}
			wire, err := EncodeStoreConfiguration(configuration)
			if err != nil {
				t.Fatal(err)
			}
			want, err := hex.DecodeString(tt.wire)
			if err != nil || !bytes.Equal(wire, want) {
				t.Fatalf("wire=%x want=%x err=%v", wire, want, err)
			}
			id, err := StoreConfigurationID(configuration)
			if err != nil || hex.EncodeToString(id[:]) != tt.digest {
				t.Fatalf("id=%x err=%v", id, err)
			}
			if decoded, err := DecodeStoreConfiguration(wire); err != nil || decoded != configuration {
				t.Fatalf("decoded=%#v err=%v", decoded, err)
			}
			key, err := StoreConfigurationKey(configuration)
			if err != nil || key != "team/prod/"+hex.EncodeToString(domain[:])+"/configuration/"+tt.digest {
				t.Fatalf("key=%q err=%v", key, err)
			}
			candidateKey, err := StoreConfigurationKeyForID(tt.provider, "team/prod", domain, id)
			if err != nil || candidateKey != key {
				t.Fatalf("candidate helper key=%q, canonical=%q, err=%v", candidateKey, key, err)
			}
			if _, err := DecodeStoreConfiguration(append(bytes.Clone(wire), 0)); err == nil {
				t.Fatal("trailing byte accepted")
			}
		})
	}
}

// full_only: false
func TestStoreConfigurationCandidateKeyBounds(t *testing.T) {
	domain, store := Hash([]byte("candidate domain")), Hash([]byte("candidate store"))
	for _, tc := range []struct {
		name     string
		provider Family
		prefix   string
		domain   ID
		store    ID
	}{
		{"zero domain", AWS, "team/prod", ID{}, store},
		{"zero store", AWS, "team/prod", domain, ID{}},
		{"unknown provider", 3, "team/prod", domain, store},
		{"empty prefix", AWS, "", domain, store},
		{"absolute prefix", AWS, "/team/prod", domain, store},
		{"empty segment", GCP, "team//prod", domain, store},
		{"gcp segment first over", GCP, strings.Repeat("a", 129), domain, store},
		{"aws prefix first over", AWS, strings.Repeat("a", MaxStorePrefixLength+1), domain, store},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if key, err := StoreConfigurationKeyForID(tc.provider, tc.prefix, tc.domain, tc.store); err == nil || key != "" {
				t.Fatalf("invalid candidate key accepted: %q, %v", key, err)
			}
		})
	}
	for _, tc := range []struct {
		provider Family
		prefix   string
	}{
		{AWS, strings.Repeat("a", MaxStorePrefixLength)},
		{GCP, strings.Join([]string{strings.Repeat("a", 128), strings.Repeat("b", 128), strings.Repeat("c", 128), strings.Repeat("d", 125)}, "/")},
	} {
		key, err := StoreConfigurationKeyForID(tc.provider, tc.prefix, domain, store)
		if err != nil || key != tc.prefix+"/"+hex.EncodeToString(domain[:])+"/configuration/"+hex.EncodeToString(store[:]) {
			t.Fatalf("maximum candidate key refused: %q, %v", key, err)
		}
	}
}

// full_only: false
func TestStoreConfigurationRejectsInvalidConstruction(t *testing.T) {
	base := StoreConfiguration{Provider: AWS, ConstructionProfile: 2, DomainID: Hash([]byte("domain")), Region: "us-east-1", Bucket: "enkv-example", PrefixBeforeHEAD: "team/prod", ExpectedOwner: "123456789012"}
	cases := []struct {
		name string
		edit func(*StoreConfiguration)
	}{
		{"zero domain", func(v *StoreConfiguration) { v.DomainID = ID{} }},
		{"old profile", func(v *StoreConfiguration) { v.ConstructionProfile = 1 }},
		{"unknown provider", func(v *StoreConfiguration) { v.Provider = 3 }},
		{"bad region", func(v *StoreConfiguration) { v.Region = "US-east-1" }},
		{"bad bucket", func(v *StoreConfiguration) { v.Bucket = "bad.bucket" }},
		{"bad prefix", func(v *StoreConfiguration) { v.PrefixBeforeHEAD = "team//prod" }},
		{"bad owner", func(v *StoreConfiguration) { v.ExpectedOwner = "123" }},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			v := base
			tt.edit(&v)
			if _, err := EncodeStoreConfiguration(v); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

// full_only: false
func TestStoreLocationCandidateOwnerDoesNotWeakenSelectedOwner(t *testing.T) {
	domain := Hash([]byte("candidate domain"))
	aws := StoreLocation{Provider: AWS, Region: "us-east-1", Bucket: "enkv-example", PrefixBeforeHEAD: "team/prod"}
	if !StoreLocationValid(aws) {
		t.Fatal("initial AWS location without owner refused")
	}
	selected := StoreConfiguration{Provider: aws.Provider, ConstructionProfile: StoreConstructionProfile, DomainID: domain,
		Region: aws.Region, Bucket: aws.Bucket, PrefixBeforeHEAD: aws.PrefixBeforeHEAD}
	if _, err := EncodeStoreConfiguration(selected); err == nil {
		t.Fatal("selected AWS configuration omitted owner")
	}
	aws.ExpectedOwner = "123456789012"
	selected.ExpectedOwner = aws.ExpectedOwner
	if !StoreLocationValid(aws) {
		t.Fatal("guarded AWS location refused")
	}
	if _, err := EncodeStoreConfiguration(selected); err != nil {
		t.Fatal("guarded AWS configuration refused", err)
	}
	aws.ExpectedOwner = "123"
	if StoreLocationValid(aws) {
		t.Fatal("invalid AWS owner admitted")
	}
	gcp := StoreLocation{Provider: GCP, Region: "us-central1", Bucket: "enkv-example-bucket", PrefixBeforeHEAD: "team/prod", ExpectedOwner: "123456789012"}
	if StoreLocationValid(gcp) {
		t.Fatal("GCP candidate owner admitted")
	}
}

// full_only: false
func TestStoreConfigurationFieldLimitsAndTruncation(t *testing.T) {
	domain := Hash([]byte("field limits"))
	gcpPrefix := strings.Join([]string{strings.Repeat("a", 128), strings.Repeat("b", 128), strings.Repeat("c", 128), strings.Repeat("d", 125)}, "/")
	cases := []struct {
		name string
		v    StoreConfiguration
	}{
		{"aws", StoreConfiguration{Provider: AWS, ConstructionProfile: 2, DomainID: domain,
			Region: "us-" + strings.Repeat("a", 27) + "-1", Bucket: "a" + strings.Repeat("b", 61) + "c",
			PrefixBeforeHEAD: strings.Repeat("p", 512), ExpectedOwner: "123456789012"}},
		{"gcp", StoreConfiguration{Provider: GCP, ConstructionProfile: 2, DomainID: domain,
			Region: "us-" + strings.Repeat("a", 60) + "1", Bucket: "a" + strings.Repeat("b", 220) + "c",
			PrefixBeforeHEAD: gcpPrefix}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !StoreLocationValid(StoreLocation{Provider: tc.v.Provider, Region: tc.v.Region, Bucket: tc.v.Bucket, PrefixBeforeHEAD: tc.v.PrefixBeforeHEAD, ExpectedOwner: tc.v.ExpectedOwner}) {
				t.Fatal("maximum selected location refused")
			}
			wire, err := EncodeStoreConfiguration(tc.v)
			if err != nil {
				t.Fatalf("maximum fields refused: %v", err)
			}
			decoded, err := DecodeStoreConfiguration(wire)
			if err != nil || decoded != tc.v {
				t.Fatalf("maximum fields did not round trip: %v", err)
			}
			for i := 0; i < len(wire); i++ {
				if _, err := DecodeStoreConfiguration(wire[:i]); err == nil {
					t.Fatalf("truncation at byte %d accepted", i)
				}
			}
			for _, mutation := range []struct {
				name string
				edit func(*StoreConfiguration)
			}{
				{"region", func(v *StoreConfiguration) { v.Region += "a" }},
				{"bucket", func(v *StoreConfiguration) { v.Bucket = v.Bucket[:len(v.Bucket)-1] + "bc" }},
				{"prefix", func(v *StoreConfiguration) { v.PrefixBeforeHEAD += "p" }},
			} {
				v := tc.v
				mutation.edit(&v)
				if StoreLocationValid(StoreLocation{Provider: v.Provider, Region: v.Region, Bucket: v.Bucket, PrefixBeforeHEAD: v.PrefixBeforeHEAD, ExpectedOwner: v.ExpectedOwner}) {
					t.Fatalf("%s first over maximum accepted as a candidate location", mutation.name)
				}
				if _, err := EncodeStoreConfiguration(v); err == nil {
					t.Fatalf("%s first over maximum accepted", mutation.name)
				}
			}
			for _, index := range []int{0, len(storeConfigurationPrefix) - 2, len(storeConfigurationPrefix) + 1, len(storeConfigurationPrefix) + 2} {
				damaged := bytes.Clone(wire)
				damaged[index] ^= 1
				if _, err := DecodeStoreConfiguration(damaged); err == nil {
					t.Fatalf("purpose/profile damage at %d accepted", index)
				}
			}
		})
	}
	for _, tc := range []struct {
		name string
		edit func(*StoreConfiguration)
	}{
		{"gcp owner", func(v *StoreConfiguration) { v.ExpectedOwner = "123456789012" }},
		{"gcp region", func(v *StoreConfiguration) { v.Region = "US-central1" }},
		{"gcp bucket", func(v *StoreConfiguration) { v.Bucket = "bad..bucket" }},
		{"gcp prefix", func(v *StoreConfiguration) { v.PrefixBeforeHEAD = "team//prod" }},
	} {
		v := cases[1].v
		tc.edit(&v)
		if _, err := EncodeStoreConfiguration(v); err == nil {
			t.Fatalf("%s accepted", tc.name)
		}
	}
}
