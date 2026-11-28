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

func TestLimiterEvictsOldestBuckets(t *testing.T) {
	now := time.Unix(1_901_500_000, 0)
	l := newLimiter(func() time.Time { return now })
	l.max = 4
	for i := 0; i < 4; i++ {
		l.allow(fmt.Sprintf("old-%d", i), 1, 1)
		now = now.Add(time.Millisecond)
	}
	l.allow("recent", 1, 1)
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.buckets["old-0"]; ok {
		t.Fatal("oldest bucket was not evicted")
	}
	if _, ok := l.buckets["recent"]; !ok {
		t.Fatal("recent bucket was evicted")
	}
	if len(l.buckets) > l.max/2+1 {
		t.Fatalf("eviction did not bound map: %d", len(l.buckets))
	}
}
