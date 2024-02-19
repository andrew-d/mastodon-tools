package helpers

import (
	"reflect"
	"sort"
	"testing"
)

func TestDiff(t *testing.T) {
	tests := []struct {
		name    string
		old     []string
		new     []string
		wantAdd []string
		wantDel []string
		final   []string
	}{
		{
			name:    "no_old",
			old:     nil,
			new:     []string{"foo"},
			wantAdd: []string{"foo"},
			final:   []string{"foo"},
		},
		{
			name:  "no_change",
			old:   []string{"foo"},
			new:   []string{"foo"},
			final: []string{"foo"},
		},
		{
			name:    "delete_one",
			old:     []string{"foo", "bar"},
			new:     []string{"foo"},
			wantDel: []string{"bar"},
			final:   []string{"foo"},
		},
		{
			name:    "change_all",
			old:     []string{"foo", "bar"},
			new:     []string{"baz", "asdf"},
			wantDel: []string{"bar", "foo"},  // sorted
			wantAdd: []string{"asdf", "baz"}, // sorted
			final:   []string{"baz", "asdf"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var added, deleted []string
			fm, err := Diff(tt.old, tt.new, func(p string) error {
				if len(deleted) > 0 {
					t.Error("delete called before add")
				}
				added = append(added, p)
				return nil
			}, func(p string) error {
				deleted = append(deleted, p)
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}

			sort.Strings(added)
			sort.Strings(deleted)

			if !reflect.DeepEqual(added, tt.wantAdd) {
				t.Errorf("added = %v, want %v", added, tt.wantAdd)
			}
			if !reflect.DeepEqual(deleted, tt.wantDel) {
				t.Errorf("deleted = %v, want %v", deleted, tt.wantDel)
			}

			// Check final state
			if len(fm) != len(tt.final) {
				t.Fatalf("final state = %v, want %v", fm, tt.final)
			}
			for _, p := range tt.final {
				if !fm[p] {
					t.Errorf("final state = %v, want %v", fm, tt.final)
				}
			}
		})
	}

}
