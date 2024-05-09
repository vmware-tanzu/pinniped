// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package totp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestGenerateOTPCode(t *testing.T) {
	tests := []struct {
		name                         string
		token                        string
		when                         time.Time
		wantCode                     string
		wantRemainingLifetimeSeconds int64
	}{
		{
			name:                         "Use a token from online example",
			token:                        "JBSWY3DPEHPK3PXP", // https://github.com/pquerna/otp/blob/3357de7c04813a328d6a1e4a514854213e0f8ce8/totp/totp.go#L180
			when:                         time.Unix(1715205169, 0),
			wantCode:                     "780919",
			wantRemainingLifetimeSeconds: 11,
		},
		{
			name:                         "Use a token that was randomly generated",
			token:                        "EDAYKXL3TEYZNQ3O4N5KPSUAQQLZYUJG",
			when:                         time.Unix(1715225917, 0),
			wantCode:                     "920615",
			wantRemainingLifetimeSeconds: 23,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			actualCode, actualRemainingLifetimeSeconds := GenerateOTPCode(t, test.token, test.when)

			require.Equal(t, test.wantCode, actualCode)
			require.Equal(t, test.wantRemainingLifetimeSeconds, actualRemainingLifetimeSeconds)
		})
	}
}
