// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package multierror

import (
	"fmt"
	"strings"
)

type multiError []error

func New() multiError { //nolint:golint // returning a private type for encapsulation purposes
	return make([]error, 0)
}

func (m *multiError) Add(err error) {
	*m = append(*m, err)
}

func (m multiError) len() int {
	return len(m)
}

func (m multiError) Error() string {
	sb := strings.Builder{}
	_, _ = fmt.Fprintf(&sb, "%d errors:", m.len())
	for _, err := range m {
		_, _ = fmt.Fprintf(&sb, "\n- %s", err.Error())
	}
	return sb.String()
}

func (m multiError) ErrOrNil() error {
	if m.len() > 0 {
		return m
	}
	return nil
}
