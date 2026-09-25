package antispam

import (
	"sync"
	"time"
)

// Limiter is a keyed token-bucket rate limiter with bounded memory.
// When the key table is full, stale buckets are swept; if it is still full,
// new keys are refused (fail closed) rather than growing without bound.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	max     int
}

type bucket struct {
	tokens float64
	last   time.Time
	cap    float64
	refill float64 // tokens per second
}

func NewLimiter(maxKeys int) *Limiter {
	return &Limiter{buckets: map[string]*bucket{}, max: maxKeys}
}

// Allow consumes one token from key's bucket of size n refilled over window.
// n <= 0 disables the limit.
func (l *Limiter) Allow(key string, n int, window time.Duration, now time.Time) bool {
	if n <= 0 || window <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	b := l.buckets[key]
	if b == nil {
		if len(l.buckets) >= l.max {
			l.sweepLocked(now)
			if len(l.buckets) >= l.max {
				return false
			}
		}
		b = &bucket{tokens: float64(n), last: now}
		l.buckets[key] = b
	}
	b.cap = float64(n)
	b.refill = float64(n) / window.Seconds()
	b.tokens = min(b.cap, b.tokens+now.Sub(b.last).Seconds()*b.refill)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Sweep drops buckets that have fully refilled (they carry no state).
func (l *Limiter) Sweep(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(now)
}

func (l *Limiter) sweepLocked(now time.Time) {
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*b.refill >= b.cap {
			delete(l.buckets, k)
		}
	}
}

// Len returns the number of tracked keys.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
