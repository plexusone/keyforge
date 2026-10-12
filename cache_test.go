package keyforge

import (
	"testing"
	"time"
)

type tick struct{ t time.Time }

func (c *tick) now() time.Time { return c.t }

func TestLRUExpiresAfterTTL(t *testing.T) {
	clk := &tick{t: time.Unix(1000, 0)}
	c := newLRU[string, int](10, time.Minute, clk.now)
	c.put("a", 1)

	clk.t = clk.t.Add(time.Minute - time.Nanosecond)
	if v, ok := c.get("a"); !ok || v != 1 {
		t.Fatalf("get before expiry = %v, %v", v, ok)
	}
	clk.t = clk.t.Add(time.Nanosecond)
	if _, ok := c.get("a"); ok {
		t.Fatal("entry survived its TTL")
	}
	if c.len() != 0 {
		t.Fatalf("len = %d, want the expired entry dropped on use", c.len())
	}
}

func TestLRUEvictsLeastRecentlyUsed(t *testing.T) {
	clk := &tick{t: time.Unix(1000, 0)}
	c := newLRU[string, int](2, time.Hour, clk.now)
	c.put("a", 1)
	c.put("b", 2)
	if _, ok := c.get("a"); !ok { // a is now more recent than b
		t.Fatal("a missing")
	}
	c.put("c", 3)
	if _, ok := c.get("b"); ok {
		t.Fatal("b was kept; it was least recently used")
	}
	for _, k := range []string{"a", "c"} {
		if _, ok := c.get(k); !ok {
			t.Fatalf("%s was evicted", k)
		}
	}
	if c.len() != 2 {
		t.Fatalf("len = %d, want the bound of 2", c.len())
	}
}

func TestLRUPutRefreshesTTLAndValue(t *testing.T) {
	clk := &tick{t: time.Unix(1000, 0)}
	c := newLRU[string, int](2, time.Minute, clk.now)
	c.put("a", 1)
	clk.t = clk.t.Add(50 * time.Second)
	c.put("a", 2)
	clk.t = clk.t.Add(50 * time.Second)
	if v, ok := c.get("a"); !ok || v != 2 {
		t.Fatalf("get = %v, %v, want the refreshed value still cached", v, ok)
	}
}

func TestLRUClear(t *testing.T) {
	clk := &tick{t: time.Unix(1000, 0)}
	c := newLRU[string, int](2, time.Hour, clk.now)
	c.put("a", 1)
	c.clear()
	if _, ok := c.get("a"); ok || c.len() != 0 {
		t.Fatal("clear left an entry")
	}
}
