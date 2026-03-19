package ocsp

import (
	"sync"
	"time"
)

// cacheEntry представляет запись в кэше
type cacheEntry struct {
	data      []byte
	timestamp time.Time
	serial    string
}

// ResponseCache реализует кэш ответов OCSP с поддержкой инвалидации
type ResponseCache struct {
	responses map[string]*cacheEntry
	mu        sync.RWMutex
	ttl       int
}

// NewResponseCache создаёт новый кэш
func NewResponseCache(ttl int) *ResponseCache {
	return &ResponseCache{
		responses: make(map[string]*cacheEntry),
		ttl:       ttl,
	}
}

// Get получает ответ из кэша, если он не устарел
func (c *ResponseCache) Get(key []byte) []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.responses[string(key)]
	if !ok {
		return nil
	}

	if time.Since(entry.timestamp) > time.Duration(c.ttl)*time.Second {
		return nil
	}

	return entry.data
}

// Set сохраняет ответ в кэш
func (c *ResponseCache) Set(key []byte, data []byte, serial string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.responses[string(key)] = &cacheEntry{
		data:      data,
		timestamp: time.Now(),
		serial:    serial,
	}
}

// InvalidateBySerial удаляет из кэша все записи для указанного серийного номера
func (c *ResponseCache) InvalidateBySerial(serial string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for key, entry := range c.responses {
		if entry.serial == serial {
			delete(c.responses, key)
		}
	}
}

// Clear очищает весь кэш
func (c *ResponseCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.responses = make(map[string]*cacheEntry)
}

// Size возвращает размер кэша
func (c *ResponseCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.responses)
}
