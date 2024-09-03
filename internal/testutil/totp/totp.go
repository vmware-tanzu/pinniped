// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package totp

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // This is an implementation of an RFC that used SHA-1
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// This code is borrowed from
// https://github.com/yitsushi/totp-cli/blob/b26f5673ae2e5cc682fc1f5ed771cb08a6403283/internal/security/otp.go
// and
// https://github.com/yitsushi/totp-cli/blob/b26f5673ae2e5cc682fc1f5ed771cb08a6403283/internal/security/error.go
// which is MIT licensed. The MIT license allows copying.
// We are choosing to copying rather than take on a whole new project dependency just for a small test helper.

const (
	mask1              = 0xf
	mask2              = 0x7f
	mask3              = 0xff
	timeSplitInSeconds = 30
	shift24            = 24
	shift16            = 16
	shift8             = 8
	sumByteLength      = 8
)

// OTPError is an error describing an error during generation.
type OTPError struct {
	Message string
}

func (e OTPError) Error() string {
	return "otp error: " + e.Message
}

// GenerateOTPCode generates a 6 digit TOTP from the secret Token.
func GenerateOTPCode(t *testing.T, token string, when time.Time) (string, int64) {
	t.Helper()

	require.NotEmpty(t, token)

	timer := uint64(math.Floor(float64(when.Unix()) / float64(timeSplitInSeconds)))
	remainingTime := timeSplitInSeconds - when.Unix()%timeSplitInSeconds

	// Remove spaces, some providers are giving us in a readable format,
	// so they add spaces in there. If it's not removed while pasting in,
	// remove it now.
	token = strings.ReplaceAll(token, " ", "")

	// It should be uppercase always
	token = strings.ToUpper(token)

	secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(token)
	require.NoError(t, err)

	length := 6

	buf := make([]byte, sumByteLength)
	mac := hmac.New(sha1.New, secretBytes)

	binary.BigEndian.PutUint64(buf, timer)
	_, _ = mac.Write(buf)
	sum := mac.Sum(nil)

	// http://tools.ietf.org/html/rfc4226#section-5.4
	offset := sum[len(sum)-1] & mask1
	value := int64(((int(sum[offset]) & mask2) << shift24) |
		((int(sum[offset+1] & mask3)) << shift16) |
		((int(sum[offset+2] & mask3)) << shift8) |
		(int(sum[offset+3]) & mask3))

	modulo := int32(value % int64(math.Pow10(length))) //nolint:gosec // the resulting number must be less than 10^6

	format := fmt.Sprintf("%%0%dd", length)

	return fmt.Sprintf(format, modulo), remainingTime
}
