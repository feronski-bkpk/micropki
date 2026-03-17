package ocsp

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// CacheEntry представляет запись в кэше
type CacheEntry struct {
	Response  []byte
	Timestamp time.Time
	TTL       int
}

// IsExpired проверяет, истекло ли время жизни записи
func (e *CacheEntry) IsExpired() bool {
	return time.Since(e.Timestamp).Seconds() > float64(e.TTL)
}

// ResponseCache реализует кэш для OCSP-ответов
type ResponseCache struct {
	entries map[string]*CacheEntry
	ttl     int
	mu      sync.RWMutex
}

// NewResponseCache создаёт новый кэш
func NewResponseCache(ttl int) *ResponseCache {
	return &ResponseCache{
		entries: make(map[string]*CacheEntry),
		ttl:     ttl,
	}
}

// Get возвращает закэшированный ответ по ключу
func (c *ResponseCache) Get(key []byte) []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()

	keyStr := c.hashKey(key)
	if entry, ok := c.entries[keyStr]; ok {
		if !entry.IsExpired() {
			return entry.Response
		}
		delete(c.entries, keyStr)
	}
	return nil
}

// Set сохраняет ответ в кэше
func (c *ResponseCache) Set(key []byte, response []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()

	keyStr := c.hashKey(key)
	c.entries[keyStr] = &CacheEntry{
		Response:  response,
		Timestamp: time.Now(),
		TTL:       c.ttl,
	}
}

// hashKey создаёт хеш ключа для безопасного хранения
func (c *ResponseCache) hashKey(key []byte) string {
	hash := sha256.Sum256(key)
	return hex.EncodeToString(hash[:])
}

// Cleanup удаляет истекшие записи
func (c *ResponseCache) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for key, entry := range c.entries {
		if entry.IsExpired() {
			delete(c.entries, key)
		}
	}
}

// Size возвращает количество записей в кэше
func (c *ResponseCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
