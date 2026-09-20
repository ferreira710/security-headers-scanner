package api

import (
	"sync"
	"time"
)

// SlidingWindowLimiter is deliberately simple: one sliding window per client,
// held in process memory.
//
// Correct for a single worker, which is what the Compose setup runs. It is a
// per-instance best effort on Netlify, where the platform may run several
// Lambda instances concurrently and none of them can see the others' counters
// -- there, the binding limit is the one configured at Netlify's edge, and
// this one only bounds what a single warm instance will do. Swapping in a
// shared store (Redis INCR + EXPIRE) is the other way out; this interface is
// what would be replaced.
type SlidingWindowLimiter struct {
	limit  int
	window time.Duration

	mu   sync.Mutex
	hits map[string][]time.Time
}

func NewSlidingWindowLimiter(limit int, window time.Duration) *SlidingWindowLimiter {
	return &SlidingWindowLimiter{limit: limit, window: window, hits: map[string][]time.Time{}}
}

// Allow records one hit for key. It returns false and the seconds to wait when
// the caller is over the limit.
func (l *SlidingWindowLimiter) Allow(key string, now time.Time) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := now.Add(-l.window)
	hits := l.hits[key]
	kept := hits[:0]
	for _, hit := range hits {
		if hit.After(cutoff) {
			kept = append(kept, hit)
		}
	}

	if len(kept) >= l.limit {
		l.hits[key] = kept
		retryAfter := int(kept[0].Add(l.window).Sub(now).Seconds()) + 1
		if retryAfter < 1 {
			retryAfter = 1
		}
		return false, retryAfter
	}

	l.hits[key] = append(kept, now)
	return true, 0
}

// Prune drops windows that fully expired, so idle clients stop costing memory.
func (l *SlidingWindowLimiter) Prune(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := now.Add(-l.window)
	for key, hits := range l.hits {
		if len(hits) == 0 || !hits[len(hits)-1].After(cutoff) {
			delete(l.hits, key)
		}
	}
}

// TrackedKeys is the number of clients currently held in memory.
func (l *SlidingWindowLimiter) TrackedKeys() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.hits)
}

// RetryAfterSeconds is the window length, the worst case a blocked caller waits.
func (l *SlidingWindowLimiter) RetryAfterSeconds() int {
	return int(l.window.Seconds())
}
