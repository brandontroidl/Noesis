// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// server/reconnect.go — Auto-reconnect with exponential backoff.
//
// When the P10 link drops, Acid waits and reconnects automatically.
// Backoff starts at 5 seconds and doubles up to 5 minutes max.
// Resets to minimum after a successful connection that lasts > 60 seconds.

package server

import (
	"log"
	"time"

	"github.com/brandontroidl/noesis/ircv3"
)

const (
	reconnectMinDelay = 5 * time.Second
	reconnectMaxDelay = 5 * time.Minute
	reconnectStableAfter = 60 * time.Second
)

// RunWithReconnect wraps Run() with automatic reconnect on failure.
// This replaces the direct Run() call in main.go.
func (s *Server) RunWithReconnect() {
	delay := reconnectMinDelay

	for {
		select {
		case <-s.shutdown:
			return
		default:
		}

		connectTime := time.Now()
		err := s.Run()

		select {
		case <-s.shutdown:
			return
		default:
		}

		if err != nil {
			log.Printf("[RECONNECT] link lost: %v", err)
		} else {
			log.Printf("[RECONNECT] link closed cleanly")
		}

		// If we were connected for a while, reset backoff
		if time.Since(connectTime) > reconnectStableAfter {
			delay = reconnectMinDelay
		}

		log.Printf("[RECONNECT] waiting %v before reconnect", delay)

		select {
		case <-s.shutdown:
			return
		case <-time.After(delay):
		}

		// Exponential backoff
		delay *= 2
		if delay > reconnectMaxDelay {
			delay = reconnectMaxDelay
		}

		// Reset state for new connection
		s.resetForReconnect()
	}
}

// resetForReconnect clears transient state before a new connection attempt.
func (s *Server) resetForReconnect() {
	s.network.Clear()
	s.batches = nil
	s.hmacActive = false

	// Re-initialize
	s.pseudoMu.Lock()
	s.pseudoClients = make(map[string]*PseudoClient)
	s.pseudoMu.Unlock()

	// Fresh shutdown channel if old one was closed
	select {
	case <-s.shutdown:
		// Already closed — we're done, don't reconnect
		return
	default:
	}

	// Recreate done channel for next Run() cycle
	s.done = make(chan struct{})

	// Reinitialize batch tracker
	s.initIRCv3State()

	log.Printf("[RECONNECT] state reset, attempting reconnect")
}

// initIRCv3State initializes/reinitializes IRCv3 tracking state.
func (s *Server) initIRCv3State() {
	s.batches = ircv3.NewBatchTracker()
}
