package yaml

import "testing"

func TestUnmarshalRejectsUnhashableKeysBesideMergeKey(t *testing.T) {
	var out map[string]any
	if err := Unmarshal([]byte("? [a, b]\n: c\n<<: {name: x}\n"), &out); err == nil {
		t.Fatal("a list key next to a merge key was accepted")
	}
}
