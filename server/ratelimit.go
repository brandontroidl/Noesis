// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// server/ratelimit.go — Token bucket rate limiter for flood control.
//
// Each user gets a bucket that refills at MaxPerSecond tokens/sec
// up to MaxBurst capacity. If a user exhausts their bucket, they
// are rate-limited for CooldownSecs before the bucket refills.

package server

import (
	"sync"
	"time"
)

// RateLimiter manages per-user rate limiting.
type RateLimiter struct {
	mu           sync.Mutex
	buckets      map[string]*bucket
	maxPerSecond float64
	maxBurst     int
	cooldownSecs int
}

type bucket struct {
	tokens   float64
	lastTime time.Time
	coolingDown bool
	cooldownEnd time.Time
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter(maxPerSecond int, maxBurst int, cooldownSecs int) *RateLimiter {
	if maxPerSecond <= 0 {
		maxPerSecond = 5
	}
	if maxBurst <= 0 {
		maxBurst = 10
	}
	if cooldownSecs <= 0 {
		cooldownSecs = 30
	}
	return &RateLimiter{
		buckets:      make(map[string]*bucket),
		maxPerSecond: float64(maxPerSecond),
		maxBurst:     maxBurst,
		cooldownSecs: cooldownSecs,
	}
}

// Allow checks if a user (identified by numeric) is allowed to
// execute a command. Returns true if allowed, false if rate-limited.
func (rl *RateLimiter) Allow(numeric string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	b, ok := rl.buckets[numeric]
	if !ok {
		b = &bucket{
			tokens:   float64(rl.maxBurst),
			lastTime: now,
		}
		rl.buckets[numeric] = b
	}

	// Check cooldown
	if b.coolingDown {
		if now.Before(b.cooldownEnd) {
			return false
		}
		// Cooldown expired — refill
		b.coolingDown = false
		b.tokens = float64(rl.maxBurst)
		b.lastTime = now
	}

	// Refill tokens based on elapsed time
	elapsed := now.Sub(b.lastTime).Seconds()
	b.tokens += elapsed * rl.maxPerSecond
	if b.tokens > float64(rl.maxBurst) {
		b.tokens = float64(rl.maxBurst)
	}
	b.lastTime = now

	// Consume a token
	if b.tokens >= 1.0 {
		b.tokens -= 1.0
		return true
	}

	// Out of tokens — enter cooldown
	b.coolingDown = true
	b.cooldownEnd = now.Add(time.Duration(rl.cooldownSecs) * time.Second)
	return false
}

// Reset clears the rate limit state for a user (e.g., on reconnect).
func (rl *RateLimiter) Reset(numeric string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.buckets, numeric)
}

// Cleanup removes stale entries older than the given duration.
func (rl *RateLimiter) Cleanup(maxAge time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	for k, b := range rl.buckets {
		if b.lastTime.Before(cutoff) {
			delete(rl.buckets, k)
		}
	}
}
