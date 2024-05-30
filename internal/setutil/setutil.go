// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package setutil

import (
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"

	"go.pinniped.dev/internal/sliceutil"
)

type CaseInsensitiveSet struct {
	lowercasedContents sets.Set[string]
}

func NewCaseInsensitiveSet(items ...string) *CaseInsensitiveSet {
	return &CaseInsensitiveSet{
		lowercasedContents: sets.New(sliceutil.Map(items, strings.ToLower)...),
	}
}

func (s *CaseInsensitiveSet) HasAnyIgnoringCase(items []string) bool {
	if s == nil {
		return false
	}
	return s.lowercasedContents.HasAny(sliceutil.Map(items, strings.ToLower)...)
}

func (s *CaseInsensitiveSet) ContainsIgnoringCase(item string) bool {
	if s == nil {
		return false
	}
	return s.lowercasedContents.Has(strings.ToLower(item))
}

func (s *CaseInsensitiveSet) Empty() bool {
	if s == nil {
		return true
	}
	return s.lowercasedContents.Len() == 0
}
