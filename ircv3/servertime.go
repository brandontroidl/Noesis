// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// ircv3/servertime.go — IRCv3 server-time tag generation and parsing.
//
// Format per IRCv3 server-time spec:
//   @time=2026-04-08T15:30:00.123Z
//
// Uses UTC, ISO 8601, with millisecond precision.
// Matches Cathexis @time generation and Synaxis ircv3_format_time().

package ircv3

import (
	"time"
)

const (
	// ServerTimeFormat is the IRCv3 server-time format string.
	// ISO 8601 with millisecond precision in UTC.
	ServerTimeFormat = "2006-01-02T15:04:05.000Z"
)

// FormatServerTime formats a time.Time as an IRCv3 server-time value.
func FormatServerTime(t time.Time) string {
	return t.UTC().Format(ServerTimeFormat)
}

// ServerTimeNow returns the current time formatted as an IRCv3 server-time value.
func ServerTimeNow() string {
	return FormatServerTime(time.Now())
}

// ParseServerTime parses an IRCv3 server-time value into a time.Time.
// Accepts both millisecond and second precision.
func ParseServerTime(s string) (time.Time, error) {
	// Try millisecond precision first
	t, err := time.Parse(ServerTimeFormat, s)
	if err != nil {
		// Fall back to second precision
		t, err = time.Parse("2006-01-02T15:04:05Z", s)
	}
	return t, err
}
