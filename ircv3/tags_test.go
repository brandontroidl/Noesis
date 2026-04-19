// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only

package ircv3

import (
	"testing"
)

func TestParseTags(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect map[string]string
	}{
		{
			name:  "empty",
			input: "",
			expect: map[string]string{},
		},
		{
			name:  "single tag with value",
			input: "time=2026-04-08T15:30:00.000Z",
			expect: map[string]string{
				"time": "2026-04-08T15:30:00.000Z",
			},
		},
		{
			name:  "multiple tags",
			input: "time=2026-04-08T15:30:00.000Z;msgid=abc123;account=nick",
			expect: map[string]string{
				"time":    "2026-04-08T15:30:00.000Z",
				"msgid":   "abc123",
				"account": "nick",
			},
		},
		{
			name:  "boolean tag no value",
			input: "draft/bot",
			expect: map[string]string{
				"draft/bot": "",
			},
		},
		{
			name:  "mixed boolean and valued",
			input: "time=2026-04-08T15:30:00.000Z;draft/bot;account=nick",
			expect: map[string]string{
				"time":      "2026-04-08T15:30:00.000Z",
				"draft/bot": "",
				"account":   "nick",
			},
		},
		{
			name:  "escaped semicolon in value",
			input: `key=val\:ue`,
			expect: map[string]string{
				"key": "val;ue",
			},
		},
		{
			name:  "escaped space in value",
			input: `key=hello\sworld`,
			expect: map[string]string{
				"key": "hello world",
			},
		},
		{
			name:  "escaped backslash",
			input: `key=back\\slash`,
			expect: map[string]string{
				"key": `back\slash`,
			},
		},
		{
			name:  "client-only tag",
			input: "+typing=active;msgid=abc",
			expect: map[string]string{
				"+typing": "active",
				"msgid":   "abc",
			},
		},
		{
			name:  "trailing semicolon",
			input: "time=now;msgid=abc;",
			expect: map[string]string{
				"time":  "now",
				"msgid": "abc",
			},
		},
		{
			name:  "batch reference",
			input: "batch=ref123;time=2026-04-08T15:30:00.000Z",
			expect: map[string]string{
				"batch": "ref123",
				"time":  "2026-04-08T15:30:00.000Z",
			},
		},
		{
			name:  "label tag for labeled-response",
			input: "label=xyzzy;time=2026-04-08T15:30:00.000Z",
			expect: map[string]string{
				"label": "xyzzy",
				"time":  "2026-04-08T15:30:00.000Z",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tags := ParseTags(tc.input)
			if tags.Len() != len(tc.expect) {
				t.Errorf("expected %d tags, got %d", len(tc.expect), tags.Len())
			}
			for k, v := range tc.expect {
				got, ok := tags.Get(k)
				if !ok {
					t.Errorf("missing key %q", k)
				} else if got != v {
					t.Errorf("key %q: expected %q, got %q", k, v, got)
				}
			}
		})
	}
}

func TestTagsString(t *testing.T) {
	tags := NewTags()
	tags.Set("time", "2026-04-08T15:30:00.000Z")
	tags.Set("msgid", "abc123")

	s := tags.String()
	// Order not guaranteed, but both must be present
	if !containsAll(s, "time=2026-04-08T15:30:00.000Z", "msgid=abc123") {
		t.Errorf("unexpected output: %s", s)
	}
}

func TestTagsPrefix(t *testing.T) {
	tags := NewTags()
	if tags.Prefix() != "" {
		t.Error("empty tags should produce empty prefix")
	}

	tags.Set("time", "now")
	p := tags.Prefix()
	if p[0] != '@' {
		t.Error("prefix must start with @")
	}
}

func TestEscapeRoundtrip(t *testing.T) {
	originals := []string{
		"hello world",
		"semi;colon",
		`back\slash`,
		"newline\nhere",
		"cr\rhere",
		"all; of\\ these\n\r",
	}
	for _, orig := range originals {
		escaped := escapeTagValue(orig)
		unescaped := unescapeTagValue(escaped)
		if unescaped != orig {
			t.Errorf("roundtrip failed: %q -> %q -> %q", orig, escaped, unescaped)
		}
	}
}

func TestClientOnlyTags(t *testing.T) {
	tags := ParseTags("+typing=active;msgid=abc;+react=thumbsup")
	co := tags.ClientOnlyTags()
	if co.Len() != 2 {
		t.Errorf("expected 2 client-only tags, got %d", co.Len())
	}
	if !co.Has("+typing") || !co.Has("+react") {
		t.Error("missing client-only tags")
	}

	sv := tags.ServerTags()
	if sv.Len() != 1 {
		t.Errorf("expected 1 server tag, got %d", sv.Len())
	}
	if !sv.Has("msgid") {
		t.Error("missing server tag 'msgid'")
	}
}

func TestMerge(t *testing.T) {
	a := ParseTags("time=now;msgid=aaa")
	b := ParseTags("msgid=bbb;account=nick")
	a.Merge(b)
	if v, _ := a.Get("msgid"); v != "bbb" {
		t.Error("merge should overwrite existing keys")
	}
	if !a.Has("account") {
		t.Error("merge should add new keys")
	}
	if !a.Has("time") {
		t.Error("merge should preserve non-overlapping keys")
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		found := false
		// Check if substring appears in s
		for i := 0; i <= len(s)-len(sub); i++ {
			if s[i:i+len(sub)] == sub {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
