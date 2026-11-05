package trie

import (
	"fmt"
	"reflect"
	"testing"
)

func TestForeachValuePreservesMappingsAndStops(t *testing.T) {
	for _, optimize := range []bool{false, true} {
		t.Run(fmt.Sprint(optimize), func(t *testing.T) {
			domains := New[int]()
			for value, pattern := range []string{"exact.test", "+.suffix.test", "*.wild.test", ".sub.test", "nested.exact.test", "single"} {
				if err := domains.Insert(pattern, value); err != nil {
					t.Fatal(err)
				}
			}
			if optimize {
				domains.Optimize()
			}
			want := map[int]int{0: 1, 1: 2, 2: 1, 3: 1, 4: 1, 5: 1}
			got := make(map[int]int)
			domains.ForeachValue(func(value int) bool {
				got[value]++
				return true
			})
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("visited values %v, want %v", got, want)
			}
			visits := 0
			domains.ForeachValue(func(int) bool {
				visits++
				return false
			})
			if visits != 1 {
				t.Fatalf("visited %d values after stopping", visits)
			}
		})
	}
	for _, domains := range []*DomainTrie[int]{nil, {}, New[int]()} {
		domains.ForeachValue(func(int) bool {
			t.Fatal("empty trie reported a value")
			return false
		})
	}
}
