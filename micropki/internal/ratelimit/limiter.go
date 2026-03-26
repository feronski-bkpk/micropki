// Package ratelimit реализует ограничитель скорости запросов (token bucket)
package ratelimit

import (
	"sync"
	"time"
)

// Limiter реализует ограничитель скорости (token bucket)
type Limiter struct {
	mu      sync.RWMutex
	clients map[string]*bucket
	rate    float64
	burst   int
}

type bucket struct {
	tokens     float64
	lastRefill time.Time
}

// NewLimiter создает новый ограничитель скорости
func NewLimiter(rate float64, burst int) *Limiter {
	if rate <= 0 {
		return nil
	}
	return &Limiter{
		clients: make(map[string]*bucket),
		rate:    rate,
		burst:   burst,
	}
}

// Allow проверяет, разрешен ли запрос для данного IP
func (l *Limiter) Allow(clientIP string) bool {
	if l == nil {
		return true
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	b, exists := l.clients[clientIP]
	now := time.Now()

	if !exists {
		l.clients[clientIP] = &bucket{
			tokens:     float64(l.burst),
			lastRefill: now,
		}
		return true
	}

	elapsed := now.Sub(b.lastRefill).Seconds()
	tokensToAdd := elapsed * l.rate

	b.tokens += tokensToAdd
	if b.tokens > float64(l.burst) {
		b.tokens = float64(l.burst)
	}
	b.lastRefill = now

	if b.tokens >= 1.0 {
		b.tokens--
		return true
	}

	return false
}

// Cleanup удаляет старые записи (можно вызывать периодически)
func (l *Limiter) Cleanup(maxAge time.Duration) {
	if l == nil {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	threshold := time.Now().Add(-maxAge)
	for ip, b := range l.clients {
		if b.lastRefill.Before(threshold) {
			delete(l.clients, ip)
		}
	}
}
