package keyforge

import (
	"container/list"
	"sync"
	"time"
)

// lru is a bounded cache whose entries also expire after a TTL. It is safe for
// concurrent use. An entry is dropped on first use after it expires, and the
// least recently used entry is dropped when the bound is exceeded.
type lru[K comparable, V any] struct {
	mu    sync.Mutex
	max   int
	ttl   time.Duration
	now   func() time.Time
	order *list.List // front is most recently used
	items map[K]*list.Element
}

type lruEntry[K comparable, V any] struct {
	key     K
	val     V
	expires time.Time
}

func newLRU[K comparable, V any](max int, ttl time.Duration, now func() time.Time) *lru[K, V] {
	return &lru[K, V]{max: max, ttl: ttl, now: now, order: list.New(), items: make(map[K]*list.Element)}
}

func (c *lru[K, V]) get(k K) (v V, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, found := c.items[k]
	if !found {
		return v, false
	}
	e := el.Value.(*lruEntry[K, V])
	if !c.now().Before(e.expires) {
		c.removeLocked(el)
		return v, false
	}
	c.order.MoveToFront(el)
	return e.val, true
}

func (c *lru[K, V]) put(k K, v V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	expires := c.now().Add(c.ttl)
	if el, found := c.items[k]; found {
		e := el.Value.(*lruEntry[K, V])
		e.val, e.expires = v, expires
		c.order.MoveToFront(el)
		return
	}
	c.items[k] = c.order.PushFront(&lruEntry[K, V]{key: k, val: v, expires: expires})
	for c.order.Len() > c.max {
		c.removeLocked(c.order.Back())
	}
}

func (c *lru[K, V]) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.order.Init()
	clear(c.items)
}

func (c *lru[K, V]) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}

func (c *lru[K, V]) removeLocked(el *list.Element) {
	e := el.Value.(*lruEntry[K, V])
	delete(c.items, e.key)
	c.order.Remove(el)
}
