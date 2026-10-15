package main

import (
	"sync"
	"time"
)

// ipRateLimiter is a token bucket per client IP. A nil limiter allows
// everything.
type ipRateLimiter struct {
	mu      sync.Mutex
	rate    float64 // tokens added per second
	burst   float64
	buckets map[string]*tokenBucket
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

// newIPRateLimiter allows perMinute requests per minute from each IP, in
// bursts of up to burst requests. It returns nil when perMinute is 0.
func newIPRateLimiter(perMinute, burst int) *ipRateLimiter {
	if perMinute <= 0 {
		return nil
	}
	return &ipRateLimiter{
		rate:    float64(perMinute) / 60,
		burst:   float64(max(burst, 1)),
		buckets: make(map[string]*tokenBucket),
	}
}

func (l *ipRateLimiter) allow(ip string, now time.Time) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[ip]
	if b == nil {
		b = &tokenBucket{tokens: l.burst, last: now}
		l.buckets[ip] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// prune forgets buckets that have refilled completely, since a full bucket
// behaves the same as a missing one.
func (l *ipRateLimiter) prune(now time.Time) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for ip, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, ip)
		}
	}
}
