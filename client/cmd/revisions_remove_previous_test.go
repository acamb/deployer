package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseRevisionNumber(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantNum int32
		wantOk  bool
	}{
		{"simple", "app-3", 3, true},
		{"multi dash", "myapp-web-12", 12, true},
		{"no dash", "app", 0, false},
		{"non numeric token", "foo-bar", 0, false},
		{"trailing dash", "app-", 0, false},
		{"zero", "app-0", 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n, ok := parseRevisionNumber(c.input)
			if ok != c.wantOk || n != c.wantNum {
				t.Errorf("parseRevisionNumber(%q) = (%d, %v), want (%d, %v)", c.input, n, ok, c.wantNum, c.wantOk)
			}
		})
	}
}

func TestPromptSelectRevisions(t *testing.T) {
	cases := []struct {
		name       string
		candidates []int32
		input      string
		want       []int32
	}{
		{"single select", []int32{3, 4}, "1\n", []int32{3}},
		{"multi select comma", []int32{3, 4, 5}, "1,3\n", []int32{3, 5}},
		{"multi select space", []int32{3, 4, 5}, "2 3\n", []int32{4, 5}},
		{"all", []int32{3, 4}, "all\n", []int32{3, 4}},
		{"empty skip", []int32{3, 4}, "\n", nil},
		{"dedup", []int32{3, 4}, "1 1 2\n", []int32{3, 4}},
		{"invalid then valid", []int32{3, 4}, "9\n1\n", []int32{3}},
		{"invalid exhausted", []int32{3, 4}, "9\nx\n0\n", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := promptSelectRevisions(c.candidates, strings.NewReader(c.input))
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("promptSelectRevisions(%v, %q) = %v, want %v", c.candidates, c.input, got, c.want)
			}
		})
	}
}
