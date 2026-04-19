// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only

package ircv3

import (
	"strings"
	"testing"
)

func TestParseP10LineNoTags(t *testing.T) {
	msg := ParseP10Line("ABAAB P #channel :Hello world")
	if msg.Source != "ABAAB" {
		t.Errorf("source: expected ABAAB, got %s", msg.Source)
	}
	if msg.Command != "P" {
		t.Errorf("command: expected P, got %s", msg.Command)
	}
	if len(msg.Params) != 2 {
		t.Fatalf("params: expected 2, got %d", len(msg.Params))
	}
	if msg.Params[0] != "#channel" {
		t.Errorf("param 0: expected #channel, got %s", msg.Params[0])
	}
	if msg.Params[1] != "Hello world" {
		t.Errorf("param 1: expected 'Hello world', got %s", msg.Params[1])
	}
	if msg.Tags != nil && msg.Tags.Len() > 0 {
		t.Error("tags should be nil or empty for untagged line")
	}
}

func TestParseP10LineWithTags(t *testing.T) {
	msg := ParseP10Line("@time=2026-04-08T15:30:00.000Z;msgid=abc123;account=nick ABAAB P #channel :Hello world")
	if msg.Tags == nil {
		t.Fatal("tags should not be nil")
	}
	if v, _ := msg.Tags.Get("time"); v != "2026-04-08T15:30:00.000Z" {
		t.Errorf("time tag: %s", v)
	}
	if v, _ := msg.Tags.Get("msgid"); v != "abc123" {
		t.Errorf("msgid tag: %s", v)
	}
	if v, _ := msg.Tags.Get("account"); v != "nick" {
		t.Errorf("account tag: %s", v)
	}
	if msg.Source != "ABAAB" {
		t.Errorf("source: %s", msg.Source)
	}
	if msg.Command != "P" {
		t.Errorf("command: %s", msg.Command)
	}
	if msg.Trailing() != "Hello world" {
		t.Errorf("trailing: %s", msg.Trailing())
	}
}

func TestParseP10LineServerMessage(t *testing.T) {
	msg := ParseP10Line("PASS :secretpassword")
	if msg.Source != "" {
		t.Errorf("PASS should have no source, got %s", msg.Source)
	}
	if msg.Command != "PASS" {
		t.Errorf("command: expected PASS, got %s", msg.Command)
	}
	if msg.Trailing() != "secretpassword" {
		t.Errorf("trailing: %s", msg.Trailing())
	}
}

func TestParseP10LineBurst(t *testing.T) {
	msg := ParseP10Line("AB B #channel 1234567890 +tnl 50 ABAAB,ABAAC:o :%test")
	if msg.Source != "AB" {
		t.Errorf("source: %s", msg.Source)
	}
	if msg.Command != "B" {
		t.Errorf("command: expected B (BURST), got %s", msg.Command)
	}
}

func TestParseP10LineBATCH(t *testing.T) {
	msg := ParseP10Line("@time=2026-04-08T15:30:00.000Z AB BA +ref123 chathistory #channel")
	if msg.Tags == nil || !msg.Tags.Has("time") {
		t.Error("should parse tags on BATCH")
	}
	if msg.Source != "AB" {
		t.Errorf("source: %s", msg.Source)
	}
	if msg.Command != "BA" {
		t.Errorf("command: expected BA, got %s", msg.Command)
	}
}

func TestBuildP10LineNoTags(t *testing.T) {
	msg := &P10Message{
		Source:  "ABAAB",
		Command: "P",
		Params:  []string{"#channel", "Hello world"},
	}
	line := msg.BuildP10Line()
	if line != "ABAAB P #channel :Hello world" {
		t.Errorf("unexpected: %s", line)
	}
}

func TestBuildP10LineWithTags(t *testing.T) {
	msg := &P10Message{
		Tags:    TagsFromMap(map[string]string{"time": "now", "msgid": "abc"}),
		Source:  "ABAAB",
		Command: "P",
		Params:  []string{"#channel", "Hello"},
	}
	line := msg.BuildP10Line()
	if !strings.HasPrefix(line, "@") {
		t.Error("should start with @")
	}
	if !strings.Contains(line, "ABAAB P #channel") {
		t.Errorf("missing P10 body: %s", line)
	}
}

func TestInjectStandardTags(t *testing.T) {
	msg := &P10Message{
		Source:  "ABAAB",
		Command: "P",
		Params:  []string{"#channel", "Hello"},
	}
	msg.InjectStandardTags()
	if !msg.Tags.Has("time") {
		t.Error("should have time tag")
	}
	if !msg.Tags.Has("msgid") {
		t.Error("should have msgid tag")
	}
	// msgid should be 32 hex chars
	mid, _ := msg.Tags.Get("msgid")
	if len(mid) != 32 {
		t.Errorf("msgid should be 32 hex chars, got %d: %s", len(mid), mid)
	}
}

func TestInjectAccountTag(t *testing.T) {
	msg := &P10Message{
		Source:  "ABAAB",
		Command: "P",
		Params:  []string{"#channel", "Hello"},
	}
	msg.InjectAccountTag("NickServ")
	if v, ok := msg.Tags.Get("account"); !ok || v != "NickServ" {
		t.Errorf("account tag: %s %v", v, ok)
	}
}

func TestParseRoundtrip(t *testing.T) {
	original := "@time=2026-04-08T15:30:00.000Z;msgid=abc123 ABAAB P #channel :Hello world"
	msg := ParseP10Line(original)
	rebuilt := msg.BuildP10Line()

	// Re-parse the rebuilt line
	msg2 := ParseP10Line(rebuilt)
	if msg2.Source != msg.Source {
		t.Errorf("source mismatch: %s vs %s", msg.Source, msg2.Source)
	}
	if msg2.Command != msg.Command {
		t.Errorf("command mismatch: %s vs %s", msg.Command, msg2.Command)
	}
	if msg2.Trailing() != msg.Trailing() {
		t.Errorf("trailing mismatch: %s vs %s", msg.Trailing(), msg2.Trailing())
	}
	if v1, _ := msg.Tags.Get("time"); v1 != "" {
		if v2, _ := msg2.Tags.Get("time"); v1 != v2 {
			t.Errorf("time tag mismatch: %s vs %s", v1, v2)
		}
	}
}

func TestIsP10Numeric(t *testing.T) {
	if !isP10Numeric("AB") {
		t.Error("AB should be numeric")
	}
	if !isP10Numeric("ABAAB") {
		t.Error("ABAAB should be numeric")
	}
	if isP10Numeric("PASS") {
		t.Error("PASS should not be numeric")
	}
	if isP10Numeric("SERVER") {
		t.Error("SERVER should not be numeric")
	}
	if isP10Numeric("A") {
		t.Error("single char should not be numeric")
	}
}
