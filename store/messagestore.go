// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// store/messagestore.go — Message history storage for CHATHISTORY.
//
// In-memory ring buffer per channel/DM with periodic JSON snapshots
// to disk. Supports all IRCv3 CHATHISTORY subcommands. No external
// dependencies — stdlib only.
//
// Storage layout on disk:
//   data/history/<channel>.json   (one file per target)

package store

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// StoredMessage represents a single message in history.
type StoredMessage struct {
	MsgID     string    `json:"msgid"`
	Time      time.Time `json:"time"`
	Source    string    `json:"source"`     // nick!ident@host or numeric
	Account  string    `json:"account"`    // IRCv3 account
	Target   string    `json:"target"`     // channel or DM target
	Command  string    `json:"command"`    // PRIVMSG, NOTICE, etc.
	Text     string    `json:"text"`
}

// MessageStore holds message history for chathistory queries.
type MessageStore struct {
	mu         sync.RWMutex
	channels   map[string]*channelHistory // normalized target -> history
	maxPerChan int                        // max messages per channel
	dataDir    string                     // disk persistence directory
	dirty      map[string]bool            // channels needing flush
	stopCh     chan struct{}
	crypto     *CryptoStore               // encryption for data at rest
}

type channelHistory struct {
	Messages []StoredMessage `json:"messages"`
}

// NewMessageStore creates a new message store.
func NewMessageStore(dataDir string, maxPerChan int, crypto *CryptoStore) *MessageStore {
	if maxPerChan <= 0 {
		maxPerChan = 10000
	}
	if dataDir == "" {
		dataDir = "data/history"
	}
	if crypto == nil {
		crypto = NewCryptoStore("")
	}

	ms := &MessageStore{
		channels:   make(map[string]*channelHistory),
		maxPerChan: maxPerChan,
		dataDir:    dataDir,
		dirty:      make(map[string]bool),
		stopCh:     make(chan struct{}),
		crypto:     crypto,
	}

	// Create data directory
	_ = os.MkdirAll(dataDir, 0750)

	// Load existing history from disk
	ms.loadAll()

	// Start periodic flush
	go ms.flushLoop()

	return ms
}

// Add stores a new message.
func (ms *MessageStore) Add(msg StoredMessage) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	key := normTarget(msg.Target)
	ch, ok := ms.channels[key]
	if !ok {
		ch = &channelHistory{}
		ms.channels[key] = ch
	}

	ch.Messages = append(ch.Messages, msg)

	// Ring buffer: trim if over max
	if len(ch.Messages) > ms.maxPerChan {
		excess := len(ch.Messages) - ms.maxPerChan
		ch.Messages = ch.Messages[excess:]
	}

	ms.dirty[key] = true
}

// Latest returns the N most recent messages for a target.
// If cursor is not empty/"*", returns messages before that msgid/timestamp.
func (ms *MessageStore) Latest(target, cursor string, limit int) []StoredMessage {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	ch := ms.channels[normTarget(target)]
	if ch == nil || len(ch.Messages) == 0 {
		return nil
	}

	msgs := ch.Messages

	// If cursor specified, find the position
	if cursor != "" && cursor != "*" {
		idx := ms.findCursorIndex(msgs, cursor)
		if idx >= 0 {
			msgs = msgs[:idx]
		}
	}

	if limit <= 0 || limit > len(msgs) {
		limit = len(msgs)
	}

	// Return last N
	start := len(msgs) - limit
	if start < 0 {
		start = 0
	}

	result := make([]StoredMessage, len(msgs[start:]))
	copy(result, msgs[start:])
	return result
}

// Before returns up to limit messages before the given cursor.
func (ms *MessageStore) Before(target, cursor string, limit int) []StoredMessage {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	ch := ms.channels[normTarget(target)]
	if ch == nil || len(ch.Messages) == 0 {
		return nil
	}

	idx := ms.findCursorIndex(ch.Messages, cursor)
	if idx <= 0 {
		return nil
	}

	start := idx - limit
	if start < 0 {
		start = 0
	}

	result := make([]StoredMessage, idx-start)
	copy(result, ch.Messages[start:idx])
	return result
}

// After returns up to limit messages after the given cursor.
func (ms *MessageStore) After(target, cursor string, limit int) []StoredMessage {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	ch := ms.channels[normTarget(target)]
	if ch == nil || len(ch.Messages) == 0 {
		return nil
	}

	idx := ms.findCursorIndex(ch.Messages, cursor)
	if idx < 0 {
		idx = 0
	} else {
		idx++ // start after cursor
	}

	end := idx + limit
	if end > len(ch.Messages) {
		end = len(ch.Messages)
	}

	if idx >= end {
		return nil
	}

	result := make([]StoredMessage, end-idx)
	copy(result, ch.Messages[idx:end])
	return result
}

// Around returns up to limit messages centered on the given cursor.
func (ms *MessageStore) Around(target, cursor string, limit int) []StoredMessage {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	ch := ms.channels[normTarget(target)]
	if ch == nil || len(ch.Messages) == 0 {
		return nil
	}

	idx := ms.findCursorIndex(ch.Messages, cursor)
	if idx < 0 {
		return ms.Latest(target, "*", limit)
	}

	half := limit / 2
	start := idx - half
	if start < 0 {
		start = 0
	}
	end := start + limit
	if end > len(ch.Messages) {
		end = len(ch.Messages)
		start = end - limit
		if start < 0 {
			start = 0
		}
	}

	result := make([]StoredMessage, end-start)
	copy(result, ch.Messages[start:end])
	return result
}

// Between returns messages between two cursors.
func (ms *MessageStore) Between(target, startCursor, endCursor string, limit int) []StoredMessage {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	ch := ms.channels[normTarget(target)]
	if ch == nil || len(ch.Messages) == 0 {
		return nil
	}

	startIdx := ms.findCursorIndex(ch.Messages, startCursor)
	endIdx := ms.findCursorIndex(ch.Messages, endCursor)

	if startIdx < 0 {
		startIdx = 0
	} else {
		startIdx++ // exclusive start
	}
	if endIdx < 0 {
		endIdx = len(ch.Messages)
	}

	// Ensure correct order
	if startIdx > endIdx {
		startIdx, endIdx = endIdx, startIdx
	}

	if startIdx >= endIdx {
		return nil
	}

	msgs := ch.Messages[startIdx:endIdx]
	if limit > 0 && limit < len(msgs) {
		msgs = msgs[:limit]
	}

	result := make([]StoredMessage, len(msgs))
	copy(result, msgs)
	return result
}

// Targets returns channels/users that have history in the given time range.
func (ms *MessageStore) Targets(from, to time.Time, limit int) []string {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	type targetInfo struct {
		name     string
		lastTime time.Time
	}

	var targets []targetInfo

	for name, ch := range ms.channels {
		if len(ch.Messages) == 0 {
			continue
		}
		// Check if any message falls in range
		for i := len(ch.Messages) - 1; i >= 0; i-- {
			msg := ch.Messages[i]
			if (msg.Time.Equal(from) || msg.Time.After(from)) &&
				(msg.Time.Equal(to) || msg.Time.Before(to)) {
				targets = append(targets, targetInfo{name, msg.Time})
				break
			}
		}
	}

	// Sort by most recent activity
	sort.Slice(targets, func(i, j int) bool {
		return targets[i].lastTime.After(targets[j].lastTime)
	})

	if limit > 0 && limit < len(targets) {
		targets = targets[:limit]
	}

	result := make([]string, len(targets))
	for i, t := range targets {
		result[i] = t.name
	}
	return result
}

// findCursorIndex finds the index of a message by msgid or timestamp cursor.
// Cursors can be:
//   - "msgid=<id>"
//   - "timestamp=<iso8601>"
//   - raw msgid string
//   - raw timestamp string
func (ms *MessageStore) findCursorIndex(msgs []StoredMessage, cursor string) int {
	if cursor == "" || cursor == "*" {
		return -1
	}

	// Try msgid= prefix
	if strings.HasPrefix(cursor, "msgid=") {
		id := cursor[6:]
		for i, m := range msgs {
			if m.MsgID == id {
				return i
			}
		}
		return -1
	}

	// Try timestamp= prefix
	if strings.HasPrefix(cursor, "timestamp=") {
		tsStr := cursor[10:]
		return ms.findByTimestamp(msgs, tsStr)
	}

	// Try as raw msgid
	for i, m := range msgs {
		if m.MsgID == cursor {
			return i
		}
	}

	// Try as raw timestamp
	return ms.findByTimestamp(msgs, cursor)
}

// findByTimestamp finds the nearest message index to a timestamp.
func (ms *MessageStore) findByTimestamp(msgs []StoredMessage, tsStr string) int {
	t, err := time.Parse("2006-01-02T15:04:05.000Z", tsStr)
	if err != nil {
		t, err = time.Parse("2006-01-02T15:04:05Z", tsStr)
	}
	if err != nil {
		// Try unix timestamp
		if unix, err2 := strconv.ParseInt(tsStr, 10, 64); err2 == nil {
			t = time.Unix(unix, 0)
		} else {
			return -1
		}
	}

	// Binary search for nearest time
	idx := sort.Search(len(msgs), func(i int) bool {
		return !msgs[i].Time.Before(t)
	})

	if idx >= len(msgs) {
		return len(msgs) - 1
	}
	return idx
}

// --- Disk persistence ---

func (ms *MessageStore) loadAll() {
	entries, err := os.ReadDir(ms.dataDir)
	if err != nil {
		return
	}

	loaded := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".json")
		path := filepath.Join(ms.dataDir, e.Name())

		data, err := ms.crypto.ReadFile(path)
		if err != nil {
			log.Printf("[STORE] failed to read %s: %v", path, err)
			continue
		}

		var ch channelHistory
		if err := json.Unmarshal(data, &ch); err != nil {
			log.Printf("[STORE] failed to parse %s: %v", path, err)
			continue
		}

		ms.channels[name] = &ch
		loaded++
	}

	if loaded > 0 {
		log.Printf("[STORE] loaded history for %d targets", loaded)
	}
}

func (ms *MessageStore) flushLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ms.stopCh:
			ms.flushAll()
			return
		case <-ticker.C:
			ms.flushDirty()
		}
	}
}

func (ms *MessageStore) flushDirty() {
	ms.mu.Lock()
	dirty := make(map[string]bool, len(ms.dirty))
	for k, v := range ms.dirty {
		dirty[k] = v
	}
	ms.dirty = make(map[string]bool)
	ms.mu.Unlock()

	for key := range dirty {
		ms.flushChannel(key)
	}
}

func (ms *MessageStore) flushAll() {
	ms.mu.RLock()
	keys := make([]string, 0, len(ms.channels))
	for k := range ms.channels {
		keys = append(keys, k)
	}
	ms.mu.RUnlock()

	for _, key := range keys {
		ms.flushChannel(key)
	}
}

func (ms *MessageStore) flushChannel(key string) {
	ms.mu.RLock()
	ch, ok := ms.channels[key]
	if !ok {
		ms.mu.RUnlock()
		return
	}
	data, err := json.Marshal(ch)
	ms.mu.RUnlock()

	if err != nil {
		log.Printf("[STORE] marshal error for %s: %v", key, err)
		return
	}

	// Sanitize key for filename (replace # with _)
	filename := sanitizeFilename(key) + ".json"
	path := filepath.Join(ms.dataDir, filename)

	if err := ms.crypto.WriteFile(path, data, 0640); err != nil {
		log.Printf("[STORE] write error for %s: %v", path, err)
	}
}

// Shutdown flushes all pending data and stops the flush loop.
func (ms *MessageStore) Shutdown() {
	close(ms.stopCh)
}

// MessageCount returns total stored messages across all targets.
func (ms *MessageStore) MessageCount() int {
	ms.mu.RLock()
	defer ms.mu.RUnlock()
	count := 0
	for _, ch := range ms.channels {
		count += len(ch.Messages)
	}
	return count
}

// TargetCount returns the number of targets with history.
func (ms *MessageStore) TargetCount() int {
	ms.mu.RLock()
	defer ms.mu.RUnlock()
	return len(ms.channels)
}

func normTarget(s string) string {
	return strings.ToLower(s)
}

func sanitizeFilename(s string) string {
	s = strings.ReplaceAll(s, "#", "_chan_")
	s = strings.ReplaceAll(s, "&", "_local_")
	s = strings.ReplaceAll(s, "+", "_plus_")
	s = strings.ReplaceAll(s, "!", "_safe_")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	return s
}

// ParseCursor parses an IRCv3 chathistory cursor string.
func ParseCursor(cursor string) (kind, value string) {
	if idx := strings.IndexByte(cursor, '='); idx >= 0 {
		return cursor[:idx], cursor[idx+1:]
	}
	return "", cursor
}

// FormatCursor creates a msgid cursor string.
func FormatCursor(msgid string) string {
	return fmt.Sprintf("msgid=%s", msgid)
}
