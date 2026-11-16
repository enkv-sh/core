package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"time"

	"enkv.sh/core/contract"
	awsprovider "enkv.sh/providers/aws"
	"enkv.sh/providers/gcp"
)

const readTransportProbeFlag = "--probe-read-transport"

// These reads establish only the current result of the selected provider call.
// They do not admit a Product operation or continue a failed test case.
func runReadTransportProbe(args []string, out io.Writer) int {
	flags := flag.NewFlagSet("read-transport", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	operation := flags.String("operation", "", "")
	region := flags.String("region", "", "")
	bucket := flags.String("bucket", "", "")
	prefix := flags.String("prefix", "", "")
	owner := flags.String("expected-owner", "", "")
	domainText := flags.String("domain", "", "")
	key := flags.String("key", "", "")
	selector := flags.String("selector", "", "")
	if flags.Parse(args) != nil || len(flags.Args()) != 0 || out == nil {
		return 2
	}
	var domain contract.ID
	var objectLimit uint32
	switch *operation {
	case "aws-store-object", "aws-candidate-head":
		location := contract.StoreLocation{Provider: contract.AWS, Region: *region, Bucket: *bucket, PrefixBeforeHEAD: *prefix, ExpectedOwner: *owner}
		if !contract.StoreLocationValid(location) || *owner == "" || *selector != "" {
			return 2
		}
		if *operation == "aws-candidate-head" {
			if *domainText != "" || *key != "" {
				return 2
			}
		} else {
			raw, err := hex.DecodeString(*domainText)
			if err != nil || len(raw) != len(domain) || hex.EncodeToString(raw) != *domainText {
				return 2
			}
			copy(domain[:], raw)
			object, err := contract.ParseStoreObjectKey(*prefix, domain, *key)
			if err != nil {
				return 2
			}
			objectLimit = min(uint32(2<<20), contract.StoreObjectLimit(object))
			if objectLimit == 0 {
				return 2
			}
		}
	case "gcp-normal-signing-key":
		if _, ok := contract.ParseGCPKeySelector(*selector, true); !ok || *region != "" || *bucket != "" || *prefix != "" || *owner != "" || *domainText != "" || *key != "" {
			return 2
		}
	default:
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	result := struct {
		Schema     string              `json:"schema"`
		Operation  string              `json:"operation"`
		ReadStatus contract.ReadStatus `json:"read_status"`
		Reason     contract.Reason     `json:"reason"`
	}{Schema: "ReadTransportDiagnostic/v1", Operation: *operation, Reason: contract.ReasonAccess}
	route := contract.Hash([]byte("enkv/test/read-transport/default/v1"))
	if *operation == "gcp-normal-signing-key" {
		selected, _ := contract.ParseGCPKeySelector(*selector, true)
		credentials, err := gcp.LoadDefaultCredentials(ctx)
		if err == nil {
			client, err := gcp.NewClient(&http.Transport{}, credentials)
			if err == nil {
				anchor, err := gcp.NewPublicSigningAnchor(ctx, gcp.PublicSigningAnchorConfig{Role: contract.NormalSigningRole, Client: client, Region: selected.Region, KeyVersion: *selector, CredentialRoute: hex.EncodeToString(route[:])})
				if err == nil {
					der, _, reason := anchor.ResolveSigningKey(ctx)
					clear(der)
					result.Reason = reason
				} else {
					result.Reason = contract.ReasonConstruction
				}
			} else {
				result.Reason = contract.ReasonConstruction
			}
		}
	} else {
		result.ReadStatus = contract.ReadUnavailable
		credentials, err := awsprovider.LoadDefaultCredentials(ctx, *region)
		if err == nil {
			transport := &http.Transport{TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}
			read := contract.ReadResult{Status: contract.ReadInvalid, Reason: contract.ReasonConstruction}
			if *operation == "aws-store-object" {
				store, err := awsprovider.NewStore(awsprovider.StoreConfig{Region: *region, Bucket: *bucket, ExpectedBucketOwner: *owner, Prefix: *prefix, Domain: domain, CredentialRoute: route, Credentials: credentials, Transport: transport, Timeout: time.Minute})
				if err == nil {
					read = store.Read(ctx, *key, objectLimit)
				}
			} else {
				reader, err := awsprovider.NewCandidateReader(awsprovider.CandidateReadConfig{Region: *region, Bucket: *bucket, ExpectedBucketOwner: *owner, Prefix: *prefix, CredentialRoute: route, Credentials: credentials, Transport: transport, Timeout: time.Minute})
				if err == nil {
					read = reader.ReadHEAD(ctx)
				}
			}
			clear(read.Body)
			result.ReadStatus, result.Reason = read.Status, read.Reason
		}
	}
	if json.NewEncoder(out).Encode(result) != nil {
		return 2
	}
	return 0
}
