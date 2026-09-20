package queue

import (
	"sync"
	"testing"
)

func TestConcurrentHistoryReadersAndWriters(t *testing.T) {
	q := New[int](10)
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for i := range 1000 {
				q.Put(i)
				q.Last()
				q.Len()
				q.Copy()
				q.Pop()
			}
		})
	}
	workers.Wait()
	if q.Len() != 0 || q.Pop() != 0 || q.Last() != 0 {
		t.Fatal("balanced history updates left queued items")
	}
}

func TestPopReleasesRemovedReference(t *testing.T) {
	q := New[*int](2)
	value := 1
	q.Put(&value)
	backing := q.items[:cap(q.items)]
	if q.Pop() != &value || backing[0] != nil {
		t.Fatal("popped reference is still retained by the backing array")
	}
}
