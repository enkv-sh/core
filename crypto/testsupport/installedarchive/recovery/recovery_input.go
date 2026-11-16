package recovery

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"enkv.sh/crypto/testsupport/installedarchive"
)

const MaximumRecoveryInputBytes = 128 << 10

func DecodeRecoveryInput(reader io.Reader) (installedarchive.RecoveryInput, error) {
	var input installedarchive.RecoveryInput
	limited := &io.LimitedReader{R: reader, N: MaximumRecoveryInputBytes + 1}
	body, err := io.ReadAll(limited)
	if err != nil || limited.N <= 0 || !uniqueRecoveryFields(body) {
		return installedarchive.RecoveryInput{}, errors.New("restricted recovery input refused")
	}
	defer clear(body)
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return installedarchive.RecoveryInput{}, errors.New("restricted recovery input refused")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF || limited.N <= 0 || !validRecoveryInput(input) {
		return installedarchive.RecoveryInput{}, errors.New("restricted recovery input refused")
	}
	return input, nil
}

func validRecoveryInput(input installedarchive.RecoveryInput) bool {
	if input.Provider != "aws" && input.Provider != "gcp" || input.Bucket == "" || input.Region == "" || input.Prefix == "" ||
		input.NormalSigner == "" && input.RecoverySigner == "" || input.ReadRoute == "" || input.SignRoute == "" || input.PrivateRoute == "" ||
		input.TimeoutMillis == 0 || input.TimeoutMillis > 60000 || !filepath.IsAbs(input.Output) {
		return false
	}
	for _, value := range []string{input.Bucket, input.Region, input.Prefix, input.Owner, input.NormalSigner, input.NormalRegion, input.RecoverySigner, input.RecoveryRegion, input.ReadRoute, input.SignRoute, input.PrivateRoute, input.AccessKey, input.SecretKey, input.NormalAccessKey, input.NormalSecretKey, input.RecoveryAccessKey, input.RecoverySecretKey, input.PrivateAccessKey, input.PrivateSecretKey, input.Token, input.ServiceAccountFile, input.NormalServiceAccountFile, input.RecoveryServiceAccountFile, input.PrivateServiceAccountFile, input.Output, input.ExpectedKEK} {
		if len(value) > 2048 || strings.ContainsAny(value, "\x00\r\n") {
			return false
		}
	}
	if (input.NormalSigner == "") != (input.NormalRegion == "") || (input.RecoverySigner == "") != (input.RecoveryRegion == "") {
		return false
	}
	if input.Responder != "" {
		host, port, err := net.SplitHostPort(input.Responder)
		portNumber, portErr := strconv.ParseUint(port, 10, 16)
		if err != nil || portErr != nil || portNumber == 0 || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
			return false
		}
	} else if input.Provider != "gcp" || input.ServiceAccountFile == "" {
		return false
	}
	if input.ServiceAccountFile != "" && ((input.Responder == "") != (len(input.TLSCertificate) == 0) || !filepath.IsAbs(input.ServiceAccountFile) || filepath.Clean(input.ServiceAccountFile) != input.ServiceAccountFile || input.Token != "" || input.Requests == 0 || input.Requests > 4096 || input.ResponseBytes == 0 || input.ResponseBytes > 8<<20 || input.BodyBytes < input.ResponseBytes) {
		return false
	}
	for _, path := range []string{input.NormalServiceAccountFile, input.RecoveryServiceAccountFile, input.PrivateServiceAccountFile} {
		if path != "" && (input.ServiceAccountFile == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path) {
			return false
		}
	}
	if input.NormalServiceAccountFile != "" && input.NormalSigner == "" || input.RecoveryServiceAccountFile != "" && input.RecoverySigner == "" {
		return false
	}
	if input.Provider == "gcp" && input.ServiceAccountFile == "" && len(input.TLSCertificate) == 0 && (input.Requests != 0 || input.BodyBytes != 0 || input.ResponseBytes != 0) {
		return false
	}
	if input.Requests != 0 && (input.Requests > 4096 || input.ResponseBytes == 0 || input.ResponseBytes > 8<<20 || input.BodyBytes < input.ResponseBytes) || input.Requests == 0 && (input.BodyBytes != 0 || input.ResponseBytes != 0) {
		return false
	}
	if len(input.SessionToken) > 16<<10 || strings.ContainsAny(input.SessionToken, "\x00\r\n") {
		return false
	}
	if input.ExpectedDomain != nil && input.ExpectedDomain.IsZero() {
		return false
	}
	for _, credential := range [][3]string{{input.AccessKey, input.SecretKey, input.SessionToken}, {input.NormalAccessKey, input.NormalSecretKey, input.NormalSessionToken}, {input.RecoveryAccessKey, input.RecoverySecretKey, input.RecoverySessionToken}, {input.PrivateAccessKey, input.PrivateSecretKey, input.PrivateSessionToken}} {
		if (credential[0] == "") != (credential[1] == "") || credential[2] != "" && credential[0] == "" || len(credential[2]) > 16<<10 || strings.ContainsAny(credential[2], "\x00\r\n") || input.Provider == "gcp" && (credential[0] != "" || credential[1] != "" || credential[2] != "") {
			return false
		}
	}
	if input.NormalAccessKey != "" && input.NormalSigner == "" || input.RecoveryAccessKey != "" && input.RecoverySigner == "" {
		return false
	}
	if input.Provider == "aws" {
		return input.AccessKey != "" && input.SecretKey != "" && input.Token == "" && input.ServiceAccountFile == "" && len(input.TLSCertificate) > 0 && len(input.TLSCertificate) <= 8<<10
	}
	return (input.Token != "" || input.ServiceAccountFile != "") && input.AccessKey == "" && input.SecretKey == "" && input.SessionToken == "" && (len(input.TLSCertificate) == 0 || input.Responder != "" && len(input.TLSCertificate) <= 8<<10 && input.Requests > 0)
}

// RecoveryEnvironment is the complete child environment. Its locations are
// created empty by the parent; no cloud, proxy or old configuration is inherited.
func RecoveryEnvironment(home, temporary string) []string {
	return []string{"HOME=" + home, "TMPDIR=" + temporary, "GORACE=log_path=stderr exitcode=66 halt_on_error=0 atexit_sleep_ms=1000", "ENKV_RESTRICTED_RECOVERY=1"}
}

func CheckRecoveryEnvironment(t testing.TB) {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRecoveryEnvironment(os.Environ(), cwd); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{cwd, os.Getenv("HOME"), os.Getenv("TMPDIR")} {
		entries, err := os.ReadDir(directory)
		if err != nil || len(entries) != 0 {
			t.Fatal("restricted child directory is not empty", err)
		}
	}
}

func validateRecoveryEnvironment(entries []string, cwd string) error {
	if len(entries) != 4 || !filepath.IsAbs(cwd) {
		return errors.New("restricted environment refused")
	}
	values := make(map[string]string, 4)
	for _, entry := range entries {
		name, value, ok := strings.Cut(entry, "=")
		if !ok || name != "HOME" && name != "TMPDIR" && name != "GORACE" && name != "ENKV_RESTRICTED_RECOVERY" {
			return errors.New("restricted environment refused")
		}
		if _, exists := values[name]; exists {
			return errors.New("restricted environment duplicate")
		}
		values[name] = value
	}
	if values["GORACE"] != "log_path=stderr exitcode=66 halt_on_error=0 atexit_sleep_ms=1000" || values["ENKV_RESTRICTED_RECOVERY"] != "1" ||
		!filepath.IsAbs(values["HOME"]) || !filepath.IsAbs(values["TMPDIR"]) ||
		values["HOME"] == values["TMPDIR"] || values["HOME"] == cwd || values["TMPDIR"] == cwd {
		return errors.New("restricted environment values refused")
	}
	return nil
}

func uniqueRecoveryFields(body []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return false
	}
	seen := make(map[string]bool)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		name, ok := token.(string)
		if !ok || seen[name] {
			return false
		}
		seen[name] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return false
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return false
	}
	var trailing any
	return decoder.Decode(&trailing) == io.EOF
}
