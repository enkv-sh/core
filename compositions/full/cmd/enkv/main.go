package main

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"strings"

	"enkv.sh/core/contract"
)

func idText(id contract.ID) string {
	if id.IsZero() {
		return ""
	}
	return hex.EncodeToString(id[:])
}

func parseID(text string) (contract.ID, bool) {
	var id contract.ID
	if len(text) != 64 || strings.ToLower(text) != text {
		return id, false
	}
	b, err := hex.DecodeString(text)
	if err != nil || len(b) != len(id) {
		return id, false
	}
	copy(id[:], b)
	return id, !id.IsZero()
}

func run(args []string, out, diagnostic io.Writer) int {
	if out == nil || diagnostic == nil {
		return 2
	}
	if handled, code := publicQueryHelp(args, out, "enkv COMMAND [OPTIONS]\nCommands: prepare init set apply plan publish generated inspect receipt manifest materialize abandon gc keys rename recipients recover rekey\nUse enkv COMMAND --help for options.\nRecognized commands use the JSON setting accepted before the first parse error; place --json before other options for structured errors.\n"); handled {
		return code
	}
	if len(args) > 0 {
		switch args[0] {
		case "prepare":
			return runPrepare(args[1:], out, diagnostic)
		case "manifest":
			return runManifest(args[1:], out, diagnostic)
		case "materialize":
			return runMaterialize(args[1:], out, diagnostic)
		case "inspect":
			return runInspect(args[1:], out, diagnostic)
		case "receipt":
			return runReceipt(args[1:], out, diagnostic)
		case "init":
			return runInit(args[1:], out, diagnostic)
		case "set":
			return runSet(args[1:], os.Stdin, out, diagnostic)
		case "apply":
			return runApply(args[1:], out, diagnostic)
		case "publish":
			return runPublish(args[1:], out, diagnostic)
		case "generated":
			return runGenerated(args[1:], out, diagnostic)
		case "plan":
			return runPlan(args[1:], out, diagnostic)
		case "abandon":
			return runAbandon(args[1:], out, diagnostic)
		case "gc":
			return runGC(args[1:], out, diagnostic)
		case "keys":
			return runKeys(args[1:], out, diagnostic)
		case "rename":
			return runLocalEdit("domain-rename", args[1:], out, diagnostic)
		case "recipients":
			return runRecipients(args[1:], out, diagnostic)
		case "recover":
			return runLocalEdit("recovery", args[1:], out, diagnostic)
		case "rekey":
			return runEnvelopeRekey(args[1:], out, diagnostic)
		}
	}
	unknownArgs := []string(nil)
	if len(args) > 0 {
		unknownArgs = args[1:]
	}
	return writeUnknownDispatch(unknownArgs, out, diagnostic)
}
func writeUnknownDispatch(args []string, out, diagnostic io.Writer) int {
	structured := commandJSONRequested(args)

	var id contract.ID
	if _, err := rand.Read(id[:]); err != nil || id.IsZero() {
		return commandDiagnosticExit(diagnostic, "request correlation unavailable", 2)
	}

	if !structured {
		body := "Command: refused\nUnsupported command. Use enkv --help to list supported commands.\n"
		n, err := io.WriteString(out, body)
		if err == nil && n == len(body) {
			return commandDiagnosticExit(diagnostic, "unsupported command", 2)
		}
		return commandDiagnosticExit(diagnostic, "result delivery failed", 2)
	}
	const prefix = "{\n  \"schema\": \"ProductResult/v1\",\n  \"operation_id\": \""
	const suffix = "\",\n  \"request_identity\": \"none\",\n  \"replay_identity\": \"none\",\n  \"state_result\": \"refused\",\n  \"effect_summary\": \"not-applicable\",\n  \"output_summary\": \"not-applicable\",\n  \"effects\": [],\n  \"outputs\": [],\n  \"duties\": [],\n  \"hazards\": [],\n  \"operation_payload\": \"none\",\n  \"capsule_policy\": \"none\",\n  \"evidence_ceiling\": \"unavailable\",\n  \"warning_summary\": []\n}\n"
	// The fifteen closed fields vary only by one 64-byte hexadecimal ID.
	// This is the complete readable count, including the final LF, at depth two.
	const length = len(prefix) + 64 + len(suffix)
	body := make([]byte, 0, length)
	body = append(body, prefix...)
	body = append(body, idText(id)...)
	body = append(body, suffix...)
	if n, err := out.Write(body); err == nil && n == len(body) {
		return commandDiagnosticExit(diagnostic, "unsupported command", 2)
	}
	return commandDiagnosticExit(diagnostic, "result delivery failed", 2)
}
func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func commandJSONRequested(args []string) bool {
	structured := false
	// An unknown operation has no flag grammar. Select only the closed output
	// convention; do not treat unsupported arguments as a recognized request.
	for _, arg := range args {
		if arg == "--" {
			break
		}
		switch arg {
		case "--json", "-json", "--json=true", "-json=true":
			structured = true
		case "--json=false", "-json=false":
			structured = false
		}
	}

	return structured
}
