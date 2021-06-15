// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package staticclient

import (
	"github.com/ory/fosite"
)

// Get returns a static client specified by the given ID.
//
// It returns a fosite.ErrNotFound if an unknown client is specified.
func Get(id string) (fosite.Client, error) {
	switch id {
	case ClientIDPinnipedCLI:
		return &PinnipedCLI{}, nil
	default:
		return nil, fosite.ErrNotFound.WithDescription("no such client")
	}
}
