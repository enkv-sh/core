package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"time"

	"enkv.sh/core/contract"
	enkvcrypto "enkv.sh/crypto"
	awsprovider "enkv.sh/providers/aws"
	"enkv.sh/providers/gcp"
)

const recipientDenialProbeFlag = "--probe-recipient-private-denial"

// This independent permission probe grants no Product selection or role. It
// resolves only the nominated recipient's public key, encrypts a bounded dummy
// packet, and requires the selected authority login to be denied its decrypt.
// The caller must separately require one authenticated permission error in capture.
func runRecipientDenialProbe(args []string, out io.Writer) int {
	flags := flag.NewFlagSet("recipient-private-denial", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	provider := flags.String("provider", "", "")
	selector := flags.String("selector", "", "")
	if flags.Parse(args) != nil || len(flags.Args()) != 0 || out == nil {
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	route := contract.Hash([]byte("enkv/test/recipient-private-denial/default/v1"))
	binding := contract.KMSBinding{BindingID: route, BindingIncarnationID: route, BindingSerial: 1, WrapProfile: contract.RSAOAEPWrapProfile, KeySelector: *selector}
	var access enkvcrypto.KeyAccess
	var public enkvcrypto.KeyResult
	if *provider == "aws" {
		selected, ok := contract.ParseAWSKeySelector(*selector, false)
		if !ok {
			return 2
		}
		credentials, err := awsprovider.LoadDefaultCredentials(ctx, selected.Region)
		if err != nil {
			return 2
		}
		config := awsprovider.KeyAccessConfig{Region: selected.Region, Account: selected.Account, CredentialRoute: route, Credentials: credentials, Timeout: 30 * time.Second, Transport: &http.Transport{TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}}
		binding.Provider = contract.AWS
		binding.SPKI, binding.Fingerprint, binding.ProtectionClass, public = awsprovider.ResolveEncryptionKey(ctx, config, *selector)
		access, err = awsprovider.NewKeyAccess(config)
		if err != nil {
			return 2
		}
	} else if *provider == "gcp" {
		selected, ok := contract.ParseGCPKeySelector(*selector, false)
		if !ok {
			return 2
		}
		credentials, err := gcp.LoadDefaultCredentials(ctx)
		if err != nil {
			return 2
		}
		client, err := gcp.NewClient(&http.Transport{}, credentials)
		if err != nil {
			return 2
		}
		config := gcp.KeyAccessConfig{Client: client, Project: selected.Project, Region: selected.Region, Endpoint: "https://" + selected.Region + "-cloudkms.googleapis.com/", CredentialRoute: route}
		binding.Provider = contract.GCP
		binding.SPKI, binding.Fingerprint, binding.ProtectionClass, public = gcp.ResolveEncryptionKey(ctx, config, *selector)
		access, err = gcp.NewKeyAccess(ctx, config)
		if err != nil {
			return 2
		}
	} else {
		return 2
	}
	if public.Status != enkvcrypto.KeyOK || access == nil {
		return 2
	}
	key, err := x509.ParsePKIXPublicKey(binding.SPKI)
	rsaKey, ok := key.(*rsa.PublicKey)
	if err != nil || !ok || rsaKey.Size() != contract.RSACiphertextLength {
		return 2
	}
	packet := make([]byte, contract.SingleKeyMaterialPacketLength)
	defer clear(packet)
	if _, err := io.ReadFull(rand.Reader, packet); err != nil {
		return 2
	}
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaKey, packet, nil)
	defer clear(ciphertext)
	if err != nil || len(ciphertext) != contract.RSACiphertextLength {
		return 2
	}
	result := access.Decrypt(ctx, binding, ciphertext, contract.SingleKeyMaterialPacketLength)
	defer clear(result.Packet)
	if ctx.Err() != nil || result.Status != enkvcrypto.KeyDenied || result.Uses.Denied != 1 || result.Uses.Completed != 0 || result.Uses.Failed != 0 || result.Uses.Unknown != 0 || len(result.Packet) != 0 {
		return 2
	}
	if json.NewEncoder(out).Encode(struct {
		Schema string `json:"schema"`
		Denied bool   `json:"denied"`
	}{"RecipientPrivateDenialProbe/v1", true}) != nil {
		return 2
	}
	return 0
}
