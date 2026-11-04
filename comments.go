package main

import "strings"

// stripLineComment removes a trailing line comment introduced by #, //, --,
// or ;. Markers inside single- or double-quoted strings are left alone so
// values like "http://example.com" and YAML/'TOML quoted scalars stay intact.
// A single slash (CIDR 10.0.0.0/8) is never treated as a comment starter.
func stripLineComment(line string) string {
	inDouble, inSingle := false, false
	escape := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if escape {
			escape = false
			continue
		}
		if inDouble {
			if c == '\\' {
				escape = true
				continue
			}
			if c == '"' {
				inDouble = false
			}
			continue
		}
		if inSingle {
			if c == '\'' {
				// YAML/TOML: '' is an escaped single quote inside '...'
				if i+1 < len(line) && line[i+1] == '\'' {
					i++
					continue
				}
				inSingle = false
			}
			continue
		}
		switch c {
		case '"':
			inDouble = true
		case '\'':
			inSingle = true
		case '#', ';':
			return strings.TrimRight(line[:i], " \t")
		case '-':
			if i+1 < len(line) && line[i+1] == '-' {
				return strings.TrimRight(line[:i], " \t")
			}
		case '/':
			if i+1 < len(line) && line[i+1] == '/' {
				return strings.TrimRight(line[:i], " \t")
			}
		}
	}
	return strings.TrimRight(line, " \t")
}

// stripComments applies stripLineComment to every line of a document.
// Used before JSON/YAML/TOML decode and for plain-text list parsing.
func stripComments(body []byte) []byte {
	lines := strings.Split(string(body), "\n")
	for i, line := range lines {
		lines[i] = stripLineComment(line)
	}
	return []byte(strings.Join(lines, "\n"))
}
