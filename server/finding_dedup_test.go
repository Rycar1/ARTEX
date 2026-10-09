package server

import (
	"encoding/json"
	"testing"
)

func TestParseFindingIDRaw(t *testing.T) {
	cases := []struct {
		raw  string
		want int64
	}{
		{"123", 123},
		{"\"456\"", 456},
		{" 789 ", 789},
		{"\" 12 \"", 12},
		{"0", 0},
		{"-3", 0},
		{"null", 0},
		{"", 0},
		{"\"abc\"", 0},
		{"12.5", 0},
	}
	for _, c := range cases {
		if got := parseFindingIDRaw(json.RawMessage(c.raw)); got != c.want {
			t.Errorf("parseFindingIDRaw(%q) = %d, want %d", c.raw, got, c.want)
		}
	}
}
