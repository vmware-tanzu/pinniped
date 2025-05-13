// Copyright 2022-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"go.pinniped.dev/internal/federationdomain/oidcclientvalidator"
)

func TestBcryptConstants(t *testing.T) {
	t.Parallel()

	// It would be helpful to know if upgrading golang changes these constants some day, so test them here for visibility during upgrades.
	require.Equal(t, 4, bcrypt.MinCost, "golang has changed bcrypt.MinCost: please consider implications to the other tests")
	require.Equal(t, 10, bcrypt.DefaultCost, "golang has changed bcrypt.DefaultCost: please consider implications to the production code and tests")
}

func TestBcryptHashedPassword1TestHelpers(t *testing.T) {
	t.Parallel()

	// Can use this to help generate or regenerate the test helper hash constants.
	// t.Log(generateHash(t, PlaintextPassword1, 12))

	require.NoError(t, bcrypt.CompareHashAndPassword([]byte(HashedPassword1AtGoMinCost), []byte(PlaintextPassword1)))
	require.NoError(t, bcrypt.CompareHashAndPassword([]byte(HashedPassword1JustBelowSupervisorMinCost), []byte(PlaintextPassword1)))
	require.NoError(t, bcrypt.CompareHashAndPassword([]byte(HashedPassword1AtSupervisorMinCost), []byte(PlaintextPassword1)))

	requireCost(t, bcrypt.MinCost, HashedPassword1AtGoMinCost)
	requireCost(t, oidcclientvalidator.DefaultMinBcryptCost-1, HashedPassword1JustBelowSupervisorMinCost)
	requireCost(t, oidcclientvalidator.DefaultMinBcryptCost, HashedPassword1AtSupervisorMinCost)
}

func TestBcryptHashedPassword2TestHelpers(t *testing.T) {
	t.Parallel()

	// Can use this to help generate or regenerate the test helper hash constants.
	// t.Log(generateHash(t, PlaintextPassword2, 12))

	require.NoError(t, bcrypt.CompareHashAndPassword([]byte(HashedPassword2AtGoMinCost), []byte(PlaintextPassword2)))
	require.NoError(t, bcrypt.CompareHashAndPassword([]byte(HashedPassword2AtSupervisorMinCost), []byte(PlaintextPassword2)))

	requireCost(t, bcrypt.MinCost, HashedPassword2AtGoMinCost)
	requireCost(t, oidcclientvalidator.DefaultMinBcryptCost, HashedPassword2AtSupervisorMinCost)
}

func generateHash(t *testing.T, password string, cost int) string { //nolint:unused // used in comments above
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	require.NoError(t, err)
	return string(hash)
}

func requireCost(t *testing.T, wantCost int, hash string) {
	cost, err := bcrypt.Cost([]byte(hash))
	require.NoError(t, err)
	require.Equal(t, wantCost, cost)
}
