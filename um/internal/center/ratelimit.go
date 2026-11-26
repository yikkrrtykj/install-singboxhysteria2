package center

import (
	"math"
	"sync"
	"time"
)

// rateLimiter is a bounded per-key token bucket for the unauthenticated ingest
// plane. Its map is capped at maxRateLimitBuckets so spoofed source keys cannot
// grow memory without bound; stale buckets are evicted first, and when every
// bucket is live the limiter fails closed with 429 rate_limited.
type rateLimiter struct {
	rate  float64
	burst float64
	now   func() time.Time

	mu      sync.Mutex
	buckets map[string]*tokenBucket
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

// newRateLimiter builds a limiter. rate <= 0 disables limiting entirely; a
// non-positive burst falls back to one token.
func newRateLimiter(rate float64, burst int, now func() time.Time) *rateLimiter {
	if now == nil {
		now = time.Now
	}
	if burst < 1 {
		burst = 1
	}
	return &rateLimiter{
		rate:    rate,
		burst:   float64(burst),
		now:     now,
		buckets: make(map[string]*tokenBucket, 64),
	}
}

// allow reports whether one request from key may proceed, and if not, the
// number of whole seconds to advertise in Retry-After.
func (l *rateLimiter) allow(key string) (bool, int) {
	if l == nil || l.rate <= 0 {
		return true, 0
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	bucket, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= maxRateLimitBuckets {
			l.evictStaleLocked(now)
			if len(l.buckets) >= maxRateLimitBuckets {
				return false, minRetryAfterSeconds
			}
		}
		bucket = &tokenBucket{tokens: l.burst, last: now}
		l.buckets[key] = bucket
	}
	if elapsed := now.Sub(bucket.last).Seconds(); elapsed > 0 {
		bucket.tokens = math.Min(l.burst, bucket.tokens+elapsed*l.rate)
		bucket.last = now
	}
	if bucket.tokens >= 1 {
		bucket.tokens--
		return true, 0
	}
	missing := 1 - bucket.tokens
	wait := int(math.Ceil(missing / l.rate))
	if wait < minRetryAfterSeconds {
		wait = minRetryAfterSeconds
	}
	return false, wait
}

// evictStaleLocked drops buckets that have not been touched for a minute. A
// bucket idle that long has fully refilled anyway, so forgetting it is
// behaviour-preserving.
func (l *rateLimiter) evictStaleLocked(now time.Time) {
	cutoff := now.Add(-time.Minute)
	for key, bucket := range l.buckets {
		if bucket.last.Before(cutoff) {
			delete(l.buckets, key)
		}
	}
}
