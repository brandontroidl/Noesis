// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// network/state.go — Network state tracking for Acid.
//
// Tracks all users, channels, and servers visible on the P10 network.
// Updated by BURST, NICK, JOIN, PART, QUIT, KICK, MODE, ACCOUNT, etc.
// Includes IRCv3 account tracking per user.

package network

import (
	"strings"
	"sync"
	"time"
)

// State holds the complete network state.
type State struct {
	mu       sync.RWMutex
	users    map[string]*User    // keyed by P10 numeric (5 chars)
	channels map[string]*Channel // keyed by normalized channel name
	servers  map[string]*Server  // keyed by P10 server numeric (2 chars)
}

// User represents a user on the network.
type User struct {
	Numeric   string    // 5-char P10 numeric
	Nick      string
	Ident     string
	Host      string    // real host
	CloakHost string    // cloaked host (+x)
	IP        string
	Gecos     string    // real name
	Modes     string    // user modes
	Account   string    // IRCv3 account name (empty if not logged in)
	Server    string    // 2-char server numeric user is on
	Timestamp time.Time // nick timestamp
	Away      string    // away message (empty if not away)
	Channels  map[string]string // channel name -> membership modes (e.g., "o", "v", "ov")
}

// Channel represents a channel on the network.
type Channel struct {
	Name      string
	Topic     string
	TopicBy   string
	TopicTime time.Time
	Modes     string
	Key       string
	Limit     int
	Timestamp time.Time // channel creation time
	Members   map[string]string // user numeric -> membership modes
	Bans      []string
	Excepts   []string
}

// Server represents a server on the network.
type Server struct {
	Numeric     string
	Name        string
	Description string
	HopCount    int
	LinkTime    time.Time
	Uplink      string // numeric of the server it's linked through
}

// New creates a new empty network state.
func New() *State {
	return &State{
		users:    make(map[string]*User),
		channels: make(map[string]*Channel),
		servers:  make(map[string]*Server),
	}
}

// --- User operations ---

// AddUser adds or updates a user.
func (s *State) AddUser(u *User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u.Channels == nil {
		u.Channels = make(map[string]string)
	}
	s.users[u.Numeric] = u
}

// RemoveUser removes a user and cleans up channel memberships.
func (s *State) RemoveUser(numeric string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[numeric]
	if !ok {
		return
	}
	// Remove from all channels
	for chName := range u.Channels {
		if ch, ok := s.channels[normChan(chName)]; ok {
			delete(ch.Members, numeric)
			// Remove empty channels
			if len(ch.Members) == 0 {
				delete(s.channels, normChan(chName))
			}
		}
	}
	delete(s.users, numeric)
}

// GetUser returns a user by numeric.
func (s *State) GetUser(numeric string) *User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.users[numeric]
}

// FindUserByNick finds a user by nick (case-insensitive).
func (s *State) FindUserByNick(nick string) *User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	lower := strings.ToLower(nick)
	for _, u := range s.users {
		if strings.ToLower(u.Nick) == lower {
			return u
		}
	}
	return nil
}

// SetUserAccount sets or clears a user's IRCv3 account.
func (s *State) SetUserAccount(numeric, account string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.users[numeric]; ok {
		u.Account = account
	}
}

// SetUserAway sets or clears a user's away status.
func (s *State) SetUserAway(numeric, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.users[numeric]; ok {
		u.Away = message
	}
}

// ChangeNick changes a user's nick.
func (s *State) ChangeNick(numeric, newNick string, ts time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.users[numeric]; ok {
		u.Nick = newNick
		u.Timestamp = ts
	}
}

// SetUserModes sets a user's mode string.
func (s *State) SetUserModes(numeric, modes string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.users[numeric]; ok {
		u.Modes = applyModes(u.Modes, modes)
	}
}

// UserCount returns the number of tracked users.
func (s *State) UserCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users)
}

// --- Channel operations ---

// AddChannel adds or updates a channel.
func (s *State) AddChannel(ch *Channel) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ch.Members == nil {
		ch.Members = make(map[string]string)
	}
	s.channels[normChan(ch.Name)] = ch
}

// GetChannel returns a channel by name.
func (s *State) GetChannel(name string) *Channel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.channels[normChan(name)]
}

// RemoveChannel removes a channel.
func (s *State) RemoveChannel(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.channels, normChan(name))
}

// JoinChannel adds a user to a channel with optional modes.
func (s *State) JoinChannel(numeric, channel, modes string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := normChan(channel)
	ch, ok := s.channels[key]
	if !ok {
		ch = &Channel{
			Name:      channel,
			Timestamp: time.Now(),
			Members:   make(map[string]string),
		}
		s.channels[key] = ch
	}
	ch.Members[numeric] = modes

	if u, ok := s.users[numeric]; ok {
		u.Channels[channel] = modes
	}
}

// PartChannel removes a user from a channel.
func (s *State) PartChannel(numeric, channel string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := normChan(channel)
	if ch, ok := s.channels[key]; ok {
		delete(ch.Members, numeric)
		if len(ch.Members) == 0 {
			delete(s.channels, key)
		}
	}
	if u, ok := s.users[numeric]; ok {
		delete(u.Channels, channel)
	}
}

// SetChannelTopic sets a channel's topic.
func (s *State) SetChannelTopic(channel, topic, setBy string, setTime time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ch, ok := s.channels[normChan(channel)]; ok {
		ch.Topic = topic
		ch.TopicBy = setBy
		ch.TopicTime = setTime
	}
}

// SetChannelModes applies mode changes to a channel.
func (s *State) SetChannelModes(channel, modes string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ch, ok := s.channels[normChan(channel)]; ok {
		ch.Modes = applyModes(ch.Modes, modes)
	}
}

// ChannelCount returns the number of tracked channels.
func (s *State) ChannelCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.channels)
}

// ChannelMembers returns the member numerics for a channel.
func (s *State) ChannelMembers(channel string) map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ch, ok := s.channels[normChan(channel)]
	if !ok {
		return nil
	}
	members := make(map[string]string, len(ch.Members))
	for k, v := range ch.Members {
		members[k] = v
	}
	return members
}

// ChannelNames returns a list of all tracked channel names.
func (s *State) ChannelNames() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	names := make([]string, 0, len(s.channels))
	for _, ch := range s.channels {
		names = append(names, ch.Name)
	}
	return names
}

// ChannelMemberCount returns the number of members in a channel.
func (s *State) ChannelMemberCount(channel string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ch, ok := s.channels[normChan(channel)]
	if !ok {
		return 0
	}
	return len(ch.Members)
}

// --- Server operations ---

// AddServer adds or updates a server.
func (s *State) AddServer(srv *Server) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.servers[srv.Numeric] = srv
}

// RemoveServer removes a server and all its users.
func (s *State) RemoveServer(numeric string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Find and remove all users on this server
	var toRemove []string
	for num, u := range s.users {
		if u.Server == numeric {
			toRemove = append(toRemove, num)
		}
	}

	// Remove users (unlock/relock not needed since we hold the lock)
	for _, num := range toRemove {
		u := s.users[num]
		for chName := range u.Channels {
			if ch, ok := s.channels[normChan(chName)]; ok {
				delete(ch.Members, num)
				if len(ch.Members) == 0 {
					delete(s.channels, normChan(chName))
				}
			}
		}
		delete(s.users, num)
	}

	delete(s.servers, numeric)
}

// GetServer returns a server by numeric.
func (s *State) GetServer(numeric string) *Server {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.servers[numeric]
}

// ServerCount returns the number of tracked servers.
func (s *State) ServerCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.servers)
}

// --- Helpers ---

// normChan normalizes a channel name for map keys (lowercase).
func normChan(name string) string {
	return strings.ToLower(name)
}

// applyModes applies a mode change string to an existing mode string.
// e.g., applyModes("oik", "+B-i") returns "okB"
func applyModes(current, change string) string {
	modes := make(map[rune]bool)
	for _, c := range current {
		if c != '+' && c != '-' {
			modes[c] = true
		}
	}

	adding := true
	for _, c := range change {
		switch c {
		case '+':
			adding = true
		case '-':
			adding = false
		default:
			if adding {
				modes[c] = true
			} else {
				delete(modes, c)
			}
		}
	}

	var result strings.Builder
	for c := range modes {
		result.WriteRune(c)
	}
	return result.String()
}

// GetAllServers returns a slice of all servers.
func (s *State) GetAllServers() []*Server {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Server, 0, len(s.servers))
	for _, srv := range s.servers {
		out = append(out, srv)
	}
	return out
}

// GetAllUsers returns a slice of all users.
func (s *State) GetAllUsers() []*User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*User, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, u)
	}
	return out
}

// Clear resets all state (used on reconnect).
func (s *State) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users = make(map[string]*User)
	s.channels = make(map[string]*Channel)
	s.servers = make(map[string]*Server)
}

// IsOper returns true if the user has IRC operator status (+o).
func (u *User) IsOper() bool {
	return strings.Contains(u.Modes, "o")
}
