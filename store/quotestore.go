// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// store/quotestore.go — Persistent quote storage.

package store

import (
	"encoding/json"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// QuoteEntry is a stored quote.
type QuoteEntry struct {
	ID        int       `json:"id"`
	Text      string    `json:"text"`
	AddedBy   string    `json:"added_by"`
	Channel   string    `json:"channel"`
	Timestamp time.Time `json:"timestamp"`
}

// QuoteStore manages persistent quote storage.
type QuoteStore struct {
	mu     sync.RWMutex
	quotes []QuoteEntry
	nextID int
	path   string
	crypto *CryptoStore
}

// NewQuoteStore creates a new quote store backed by a JSON file.
func NewQuoteStore(path string, crypto *CryptoStore) *QuoteStore {
	if path == "" {
		path = "data/quotes.json"
	}
	if crypto == nil {
		crypto = NewCryptoStore("")
	}

	qs := &QuoteStore{
		path:   path,
		nextID: 1,
		crypto: crypto,
	}

	qs.load()
	return qs
}

// Add stores a new quote and persists to disk.
func (qs *QuoteStore) Add(text, addedBy, channel string) int {
	qs.mu.Lock()
	defer qs.mu.Unlock()

	entry := QuoteEntry{
		ID:        qs.nextID,
		Text:      text,
		AddedBy:   addedBy,
		Channel:   channel,
		Timestamp: time.Now(),
	}

	qs.quotes = append(qs.quotes, entry)
	qs.nextID++
	qs.save()
	return entry.ID
}

// Get returns a quote by ID.
func (qs *QuoteStore) Get(id int) *QuoteEntry {
	qs.mu.RLock()
	defer qs.mu.RUnlock()

	for i := range qs.quotes {
		if qs.quotes[i].ID == id {
			q := qs.quotes[i]
			return &q
		}
	}
	return nil
}

// Random returns a random quote. Returns nil if no quotes exist.
func (qs *QuoteStore) Random() *QuoteEntry {
	qs.mu.RLock()
	defer qs.mu.RUnlock()

	if len(qs.quotes) == 0 {
		return nil
	}

	q := qs.quotes[rand.Intn(len(qs.quotes))]
	return &q
}

// Delete removes a quote by ID and persists.
func (qs *QuoteStore) Delete(id int) bool {
	qs.mu.Lock()
	defer qs.mu.Unlock()

	for i := range qs.quotes {
		if qs.quotes[i].ID == id {
			qs.quotes = append(qs.quotes[:i], qs.quotes[i+1:]...)
			qs.save()
			return true
		}
	}
	return false
}

// Count returns the number of stored quotes.
func (qs *QuoteStore) Count() int {
	qs.mu.RLock()
	defer qs.mu.RUnlock()
	return len(qs.quotes)
}

// Search returns quotes containing the search text (case-insensitive).
func (qs *QuoteStore) Search(text string) []QuoteEntry {
	qs.mu.RLock()
	defer qs.mu.RUnlock()

	var results []QuoteEntry
	lower := strings.ToLower(text)
	for _, q := range qs.quotes {
		if strings.Contains(strings.ToLower(q.Text), lower) {
			results = append(results, q)
		}
	}
	return results
}

func (qs *QuoteStore) load() {
	data, err := qs.crypto.ReadFile(qs.path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[QUOTES] load error: %v", err)
		}
		return
	}

	if err := json.Unmarshal(data, &qs.quotes); err != nil {
		log.Printf("[QUOTES] parse error: %v", err)
		return
	}

	// Find highest ID for nextID
	for _, q := range qs.quotes {
		if q.ID >= qs.nextID {
			qs.nextID = q.ID + 1
		}
	}

	log.Printf("[QUOTES] loaded %d quotes", len(qs.quotes))
}

func (qs *QuoteStore) save() {
	data, err := json.MarshalIndent(qs.quotes, "", "  ")
	if err != nil {
		log.Printf("[QUOTES] marshal error: %v", err)
		return
	}

	// Ensure directory exists
	dir := filepath.Dir(qs.path)
	_ = os.MkdirAll(dir, 0750)

	if err := qs.crypto.WriteFile(qs.path, data, 0640); err != nil {
		log.Printf("[QUOTES] write error: %v", err)
	}
}
