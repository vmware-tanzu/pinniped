// Copyright 2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package psets

import (
	"reflect"
	"sort"
)

// These were copied from https://github.com/kubernetes/kubernetes/tree/v1.25.5/staging/src/k8s.io/apimachinery/pkg/util/sets
// which is the last version before they were converted to generic functions which require the use
// of Go 1.18+ to compile. This is not a full copy of the files from k/k, but rather only copies of the
// functions that we actually use. When we are ready to require the use of Go 1.18+ to compile Pinniped,
// then we can go back to using the version of this package from the k8s libraries. Our use
// of this package was very minimal, so its easy enough to just copy the few functions that we were
// actually using to keep Go 1.17 compatibility a little longer.

// Empty is public since it is used by some internal API objects for conversions between external
// string arrays and internal sets, and conversion logic requires public types today.
type Empty struct{}

// sets.String is a set of strings, implemented via map[string]struct{} for minimal memory consumption.
type String map[string]Empty

// StringKeySet creates a String from a keys of a map[string](? extends interface{}).
// If the value passed in is not actually a map, this will panic.
func StringKeySet(theMap interface{}) String {
	v := reflect.ValueOf(theMap)
	ret := String{}

	for _, keyValue := range v.MapKeys() {
		ret.Insert(keyValue.Interface().(string))
	}
	return ret
}

// Insert adds items to the set.
func (s String) Insert(items ...string) String {
	for _, item := range items {
		s[item] = Empty{}
	}
	return s
}

// Has returns true if and only if item is contained in the set.
func (s String) Has(item string) bool {
	_, contained := s[item]
	return contained
}

type sortableSliceOfString []string

func (s sortableSliceOfString) Len() int           { return len(s) }
func (s sortableSliceOfString) Less(i, j int) bool { return lessString(s[i], s[j]) }
func (s sortableSliceOfString) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

// List returns the contents as a sorted string slice.
func (s String) List() []string {
	res := make(sortableSliceOfString, 0, len(s))
	for key := range s {
		res = append(res, key)
	}
	sort.Sort(res)
	return []string(res)
}

func lessString(lhs, rhs string) bool {
	return lhs < rhs
}
