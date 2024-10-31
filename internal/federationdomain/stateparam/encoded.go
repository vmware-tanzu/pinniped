// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package stateparam

import (
	"crypto/sha256"
	"fmt"
)

type Encoded string

func (e Encoded) String() string {
	return string(e)
}

func (e Encoded) AuthorizeID() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(e)))
}
