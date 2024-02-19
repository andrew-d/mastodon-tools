package helpers

import (
	"errors"
	"maps"
)

// Diff calls add and del as needed to make the set of values in old and new
// match. It returns a map reflecting the actual new state (which may be
// somewhere in between old and new if some commands failed), and any error
// encountered while making changes.
func Diff[T comparable](old, new []T, add, del func(T) error) (map[T]bool, error) {
	// Start by making things into maps
	oldMap := make(map[T]bool, len(new))
	for _, vv := range old {
		oldMap[vv] = true
	}
	newMap := make(map[T]bool, len(new))
	for _, vv := range new {
		newMap[vv] = true
	}

	// ret starts out as a copy of old, and is updates as we add/delete.
	// That way we can always return it and have it be the true state of
	// what we've done so far.
	ret := maps.Clone(oldMap)

	// Always add before we delete, so we don't end up in a situation where
	// we have removed everything.
	var addErrs []error
	for vv := range newMap {
		if oldMap[vv] {
			continue
		}
		if err := add(vv); err != nil {
			addErrs = append(addErrs, err)
		} else {
			ret[vv] = true
		}
	}

	if len(addErrs) > 0 {
		return ret, errors.Join(addErrs...)
	}

	var delErrs []error
	for vv := range oldMap {
		if newMap[vv] {
			continue
		}
		if err := del(vv); err != nil {
			delErrs = append(delErrs, err)
		} else {
			delete(ret, vv)
		}
	}
	if len(delErrs) > 0 {
		return ret, errors.Join(delErrs...)
	}

	return ret, nil
}
