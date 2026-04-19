// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// modules/util.go — shared utility helpers across Noesis modules.

package modules

import "strings"

// matchWild returns true if str matches the glob pattern pattern.
// Supports '*' (any run, including empty) and '?' (any one char).
// Case-insensitive by design — IRC masks (nick!user@host) are commonly compared
// without case sensitivity.
func matchWild(pattern, str string) bool {
	return matchWildR(strings.ToLower(pattern), strings.ToLower(str))
}

func matchWildR(p, s string) bool {
	for len(p) > 0 {
		switch p[0] {
		case '*':
			for len(p) > 1 && p[1] == '*' {
				p = p[1:]
			}
			if len(p) == 1 {
				return true
			}
			for i := 0; i <= len(s); i++ {
				if matchWildR(p[1:], s[i:]) {
					return true
				}
			}
			return false
		case '?':
			if len(s) == 0 {
				return false
			}
			p = p[1:]
			s = s[1:]
		default:
			if len(s) == 0 || p[0] != s[0] {
				return false
			}
			p = p[1:]
			s = s[1:]
		}
	}
	return len(s) == 0
}
