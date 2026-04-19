// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// server/hooks.go — Event hook system for modules.
//
// Modules register callbacks for network events (JOIN, PART, QUIT, etc.)
// The server fires these hooks from the appropriate message handlers.
// This is what lets TrapBot react to JOINs, LimitServ react to
// membership changes, etc.

package server

import (
	"sync"

	"github.com/brandontroidl/noesis/ircv3"
)

// EventType identifies the type of network event.
type EventType int

const (
	EventJoin    EventType = iota
	EventPart
	EventQuit
	EventKick
	EventNick
	EventMode
	EventTopic
	EventAccount
	EventAway
	EventKill
	EventServerLink
	EventServerSplit
	EventMessage
	EventWallops
	EventNotice
	EventConnect
	EventGline
	EventShun
)

// EventHook is a callback for a network event.
type EventHook func(s *Server, msg *ircv3.P10Message)

// HookManager manages event hook registrations.
type HookManager struct {
	mu    sync.RWMutex
	hooks map[EventType][]EventHook
}

// NewHookManager creates a new hook manager.
func NewHookManager() *HookManager {
	return &HookManager{
		hooks: make(map[EventType][]EventHook),
	}
}

// Register adds a hook for the given event type.
func (hm *HookManager) Register(event EventType, hook EventHook) {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	hm.hooks[event] = append(hm.hooks[event], hook)
}

// Fire calls all hooks registered for the given event type.
func (hm *HookManager) Fire(event EventType, s *Server, msg *ircv3.P10Message) {
	hm.mu.RLock()
	hooks := hm.hooks[event]
	hm.mu.RUnlock()

	for _, hook := range hooks {
		hook(s, msg)
	}
}

// HookableModule is an optional interface modules can implement
// to register event hooks during initialization.
type HookableModule interface {
	RegisterHooks(hm *HookManager)
}
