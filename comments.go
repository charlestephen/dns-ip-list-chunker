package main

import (
	"bytes"
	"strings"
)

// stripLineComment removes a trailing line comment introduced by #, //, --,
// or ;. Markers inside single- or double-quoted strings are left alone so
// values like "http://example.com" stay intact.
//
// // and -- only count when they start the line or follow whitespace, so
// domains like o--o.duckdns.org and xn--punycode.example survive. A single
// slash (CIDR 10.0.0.0/8) is never a comment starter.
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
			if i+1 < len(line) && line[i+1] == '-' && commentBoundary(line, i) {
				return strings.TrimRight(line[:i], " \t")
			}
		case '/':
			if i+1 < len(line) && line[i+1] == '/' && commentBoundary(line, i) {
				return strings.TrimRight(line[:i], " \t")
			}
		}
	}
	return strings.TrimRight(line, " \t")
}

// commentBoundary reports whether index i may start a // or -- comment:
// beginning of line or immediately after ASCII whitespace.
func commentBoundary(line string, i int) bool {
	if i == 0 {
		return true
	}
	prev := line[i-1]
	return prev == ' ' || prev == '\t'
}

// stripComments applies stripLineComment to every line of a document.
// Used before JSON/YAML/TOML/CSV decode. Bodies with no comment marker at
// all are returned untouched.
func stripComments(body []byte) []byte {
	if bytes.IndexAny(body, "#;") < 0 && !bytes.Contains(body, []byte("//")) && !bytes.Contains(body, []byte("--")) {
		return body
	}
	rest := string(body)
	out := make([]byte, 0, len(rest))
	for len(rest) > 0 {
		line, tail, found := strings.Cut(rest, "\n")
		out = append(out, stripLineComment(line)...)
		if found {
			out = append(out, '\n')
		}
		rest = tail
	}
	return out
}
