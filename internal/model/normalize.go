package model

import (
	"bytes"
	"encoding/json"
	"strings"
)

// NormalizeContent applies deterministic text normalization:
// - Standardizes newlines to \n
// - Removes trailing whitespace per line
// - Trims excessive blank lines (more than 2 consecutive newlines reduced to 2)
// - Trims leading and trailing whitespace of the whole string
func NormalizeContent(s string) string {
	// Standardize line endings
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")

	lines := strings.Split(s, "\n")
	normLines := make([]string, len(lines))
	for i, line := range lines {
		normLines[i] = strings.TrimRight(line, " \t")
	}

	result := strings.Join(normLines, "\n")

	// Collapse > 2 consecutive newlines to 2
	for strings.Contains(result, "\n\n\n") {
		result = strings.ReplaceAll(result, "\n\n\n", "\n\n")
	}

	return strings.TrimSpace(result)
}

// NormalizeJSON formats JSON deterministically if s is valid JSON.
func NormalizeJSON(s string) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, []byte(s), "", "  "); err == nil {
		return buf.String()
	}
	return NormalizeContent(s)
}
