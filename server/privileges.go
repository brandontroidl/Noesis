// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// server/privileges.go — 7-tier privilege enforcement.
//
// Tier 1: Owner     — Full control
// Tier 2: Admin     — Server administration
// Tier 3: Oper      — IRC operator privileges
// Tier 4: ChanAdmin — Channel service administration
// Tier 5: Helper    — Limited support commands
// Tier 6: Authed    — Logged-in users (have an account)
// Tier 7: Unauthed  — Everyone else

package server

import (
	"strings"
)

// PrivTier represents a privilege tier (lower = more privileged).
type PrivTier int

const (
	PrivOwner     PrivTier = 1
	PrivAdmin     PrivTier = 2
	PrivOper      PrivTier = 3
	PrivChanAdmin PrivTier = 4
	PrivHelper    PrivTier = 5
	PrivAuthed    PrivTier = 6
	PrivUnauthed  PrivTier = 7
)

// String returns the tier name.
func (p PrivTier) String() string {
	switch p {
	case PrivOwner:
		return "owner"
	case PrivAdmin:
		return "admin"
	case PrivOper:
		return "oper"
	case PrivChanAdmin:
		return "chan_admin"
	case PrivHelper:
		return "helper"
	case PrivAuthed:
		return "authenticated"
	case PrivUnauthed:
		return "unauthenticated"
	default:
		return "unknown"
	}
}

// GetUserPrivilege returns the privilege tier for a user by account name.
func (s *Server) GetUserPrivilege(account string) PrivTier {
	if account == "" {
		return PrivUnauthed
	}

	cfg := s.config.Services.Privileges
	lower := strings.ToLower(account)

	for _, name := range cfg.Owners {
		if strings.ToLower(name) == lower {
			return PrivOwner
		}
	}
	for _, name := range cfg.Admins {
		if strings.ToLower(name) == lower {
			return PrivAdmin
		}
	}
	for _, name := range cfg.Opers {
		if strings.ToLower(name) == lower {
			return PrivOper
		}
	}
	for _, name := range cfg.ChanAdmins {
		if strings.ToLower(name) == lower {
			return PrivChanAdmin
		}
	}
	for _, name := range cfg.Helpers {
		if strings.ToLower(name) == lower {
			return PrivHelper
		}
	}

	return PrivAuthed
}

// GetUserPrivilegeByNumeric looks up account from network state and returns tier.
func (s *Server) GetUserPrivilegeByNumeric(numeric string) PrivTier {
	u := s.network.GetUser(numeric)
	if u == nil {
		return PrivUnauthed
	}
	return s.GetUserPrivilege(u.Account)
}

// CheckPrivilege returns true if the user meets the required tier.
func (s *Server) CheckPrivilege(numeric string, required PrivTier) bool {
	return s.GetUserPrivilegeByNumeric(numeric) <= required
}

// RequirePrivilege checks privilege and sends an error if insufficient.
// Returns true if the user has the required privilege.
func (s *Server) RequirePrivilege(sourceNumeric, replyTarget, botNumeric string, required PrivTier) bool {
	if s.CheckPrivilege(sourceNumeric, required) {
		return true
	}

	s.SendNotice(botNumeric, sourceNumeric,
		"Permission denied. This command requires "+required.String()+" access or higher.")
	return false
}
