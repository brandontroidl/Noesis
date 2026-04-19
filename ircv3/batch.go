// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// ircv3/batch.go — IRCv3 batch tracking for P10 relay.
//
// Cathexis sends BATCH +refid type [params] / BATCH -refid on P10 lines.
// Acid must track active batches so it can:
//   1. Understand which messages belong to a batch (via @batch=refid tag)
//   2. Avoid acting on messages inside certain batch types (e.g., netsplit replay)
//   3. Generate its own batch wrappers when sending multi-message responses
//      (e.g., chathistory results via XREPLY)
//
// Batch types relevant to Acid:
//   - chathistory: historical message replay
//   - netsplit / netjoin: server link changes
//   - labeled-response: responses to labeled commands
//
// Wire format:
//   BATCH +refid type [param...]    (start)
//   @batch=refid ... message ...    (member)
//   BATCH -refid                    (end)

package ircv3

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
)

// BatchType constants for recognized batch types.
const (
	BatchChatHistory     = "chathistory"
	BatchNetsplit        = "netsplit"
	BatchNetjoin         = "netjoin"
	BatchLabeledResponse = "labeled-response"
)

// Batch represents an active IRCv3 batch.
type Batch struct {
	RefID  string   // The reference identifier (e.g., "abc123")
	Type   string   // The batch type (e.g., "chathistory")
	Params []string // Additional parameters
}

// BatchTracker tracks active batches received from Cathexis.
type BatchTracker struct {
	mu      sync.RWMutex
	batches map[string]*Batch // keyed by refID
}

// NewBatchTracker creates a new batch tracker.
func NewBatchTracker() *BatchTracker {
	return &BatchTracker{
		batches: make(map[string]*Batch),
	}
}

// Start registers a new batch. Called when receiving BATCH +refid type [params].
func (bt *BatchTracker) Start(refID, batchType string, params []string) {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	bt.batches[refID] = &Batch{
		RefID:  refID,
		Type:   batchType,
		Params: params,
	}
}

// End removes a batch. Called when receiving BATCH -refid.
func (bt *BatchTracker) End(refID string) *Batch {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	b, ok := bt.batches[refID]
	if ok {
		delete(bt.batches, refID)
	}
	return b
}

// Get returns the batch for a given refID, or nil if not active.
func (bt *BatchTracker) Get(refID string) *Batch {
	bt.mu.RLock()
	defer bt.mu.RUnlock()
	return bt.batches[refID]
}

// IsInBatch returns true if a message with the given batch= tag value
// belongs to an active batch, and returns that batch.
func (bt *BatchTracker) IsInBatch(tags *Tags) (*Batch, bool) {
	if tags == nil {
		return nil, false
	}
	refID, ok := tags.Get("batch")
	if !ok || refID == "" {
		return nil, false
	}
	b := bt.Get(refID)
	return b, b != nil
}

// GenerateRefID creates a new unique batch reference ID.
// 8 random hex chars, matching Cathexis ircd_batch.c format.
func GenerateRefID() string {
	var buf [4]byte
	_, _ = rand.Read(buf[:])
	return hex.EncodeToString(buf[:])
}

// ActiveCount returns the number of currently active batches.
func (bt *BatchTracker) ActiveCount() int {
	bt.mu.RLock()
	defer bt.mu.RUnlock()
	return len(bt.batches)
}
