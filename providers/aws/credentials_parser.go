package awsprovider

import "bytes"

type sharedCredentials struct {
	accessKeyID     string
	secretAccessKey string
	sessionToken    string
}

func parseOwnedSharedCredentials(input []byte, profile string) (sharedCredentials, bool) {
	defer clearCredentialBytes(input)
	return parseSharedCredentials(input, profile)
}

func parseSharedCredentials(input []byte, profile string) (sharedCredentials, bool) {
	if !validProfileName([]byte(profile)) || !asciiCredentialInput(input) {
		return sharedCredentials{}, false
	}

	var result sharedCredentials
	var selected, found bool
	seen := make(map[string]bool, 3)
	for _, raw := range bytes.Split(input, []byte{'\n'}) {
		if len(raw) > 0 && raw[len(raw)-1] == '\r' {
			raw = raw[:len(raw)-1]
		}
		if bytes.IndexByte(raw, '\r') >= 0 {
			return sharedCredentials{}, false
		}
		trimmed := trimHorizontal(raw)
		if len(trimmed) == 0 || trimmed[0] == '#' || trimmed[0] == ';' {
			continue
		}
		line := trimHorizontal(trimInlineComment(raw))
		if len(line) == 0 {
			continue
		}
		if line[0] == '[' {
			name, ok := parseProfileSection(line)
			if !ok {
				if selected {
					return sharedCredentials{}, false
				}
				selected = false
				continue
			}
			selected = string(name) == profile
			if selected {
				if found {
					return sharedCredentials{}, false
				}
				found = true
			}
			continue
		}
		if !selected {
			continue
		}
		if raw[0] == ' ' || raw[0] == '\t' {
			return sharedCredentials{}, false
		}
		i := bytes.IndexByte(line, '=')
		if i < 0 {
			return sharedCredentials{}, false
		}
		key := lowerASCII(trimHorizontal(line[:i]))
		value := trimHorizontal(line[i+1:])
		if len(key) == 0 || len(value) == 0 || seen[string(key)] {
			return sharedCredentials{}, false
		}
		seen[string(key)] = true
		switch string(key) {
		case "aws_access_key_id":
			result.accessKeyID = string(value)
		case "aws_secret_access_key":
			result.secretAccessKey = string(value)
		case "aws_session_token":
			result.sessionToken = string(value)
		default:
			return sharedCredentials{}, false
		}
	}
	return result, found && result.accessKeyID != "" && result.secretAccessKey != ""
}

func asciiCredentialInput(input []byte) bool {
	for i, b := range input {
		if b != '\t' && b != '\n' && b != '\r' && (b < 0x20 || b > 0x7e) {
			return false
		}
		if b == '\r' && (i+1 == len(input) || input[i+1] != '\n') {
			return false
		}
	}
	return true
}

func parseProfileSection(line []byte) ([]byte, bool) {
	if len(line) < 3 || line[len(line)-1] != ']' {
		return nil, false
	}
	name := line[1 : len(line)-1]
	return name, validProfileName(name)
}

func validProfileName(name []byte) bool {
	if len(name) == 0 {
		return false
	}
	for _, b := range name {
		if (b < 'a' || b > 'z') && (b < 'A' || b > 'Z') && (b < '0' || b > '9') && b != '-' && b != '_' {
			return false
		}
	}
	return true
}

func trimInlineComment(line []byte) []byte {
	for i := 1; i < len(line); i++ {
		if (line[i] == '#' || line[i] == ';') && (line[i-1] == ' ' || line[i-1] == '\t') {
			return line[:i]
		}
	}
	return line
}

func trimHorizontal(b []byte) []byte {
	return bytes.Trim(b, " \t")
}

func lowerASCII(b []byte) []byte {
	result := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		result[i] = c
	}
	return result
}
