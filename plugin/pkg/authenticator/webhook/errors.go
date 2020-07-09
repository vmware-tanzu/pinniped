/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package webhook

import "fmt"

// These errors are mostly here to please the linter.

type tokenReviewError struct {
	errorMsg string
}

func (e tokenReviewError) Error() string {
	return fmt.Sprintf("token review error: %s", e.errorMsg)
}

type tokenReviewUnauthenticatedError struct {
}

func (e tokenReviewUnauthenticatedError) Error() string {
	return "token review is unauthenticated"
}
