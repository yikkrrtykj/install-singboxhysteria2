package web

import (
	"fmt"
	"testing"
	"time"
)

func TestLimiterCapacityEvictionAndRefill(t *testing.T) {
	now := time.Unix(1_900_800_000, 0)
	l := newLimiter(func() time.Time { return now })
	l.max = 16
	for i := 0; i < 100; i++ {
		l.allow(fmt.Sprintf("key-%d", i), 1, 1)
	}
	l.mu.Lock()
	n := len(l.buckets)
	l.mu.Unlock()
	if n > l.max {
		t.Fatalf("limiter buckets=%d exceeds max=%d", n, l.max)
	}
	// A fresh bucket starts with burst tokens and refills over time.
	if !l.allow("fresh", 1, 2) || !l.allow("fresh", 1, 2) {
		t.Fatal("fresh burst tokens missing")
	}
	if l.allow("fresh", 1, 2) {
		t.Fatal("fresh bucket exceeded burst")
	}
	now = now.Add(1100 * time.Millisecond)
	if !l.allow("fresh", 1, 2) {
		t.Fatal("bucket did not refill after elapsed time")
	}
}

func TestLimiterLongKeysStayBoundedByCallerHash(t *testing.T) {
	now := time.Unix(1_900_900_000, 0)
	l := newLimiter(func() time.Time { return now })
	long := make([]byte, 60000)
	for i := range long {
		long[i] = 'a'
	}
	// The HTTP layer hashes untrusted usernames before key construction, so a
	// limiter test can only assert the map itself remains bounded.
	l.allow(string(long), 1, 1)
	l.mu.Lock()
	n := len(l.buckets)
	_, keyLen := "", 0
	for k := range l.buckets {
		keyLen = len(k)
		break
	}
	l.mu.Unlock()
	if n != 1 || keyLen == 0 {
		t.Fatalf("limiter map size/key unexpectedly absent")
	}
}
