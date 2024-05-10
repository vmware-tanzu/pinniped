// Copyright 2023-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package backoff

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/wait"
)

type MockStepper struct {
	steps       []time.Duration
	currentStep int
}

func (m *MockStepper) Step() time.Duration {
	result := m.steps[m.currentStep]
	m.currentStep++
	return result
}

func TestWithContext(t *testing.T) {
	tests := []struct {
		name           string
		steps          []time.Duration
		finalCondition wait.ConditionWithContextFunc
		expectedErr    error
	}{
		{
			name: "cancelling results in cancellation error",
			steps: []time.Duration{
				time.Duration(0),
				time.Duration(0),
				time.Duration(0),
			},
			finalCondition: func(ctx context.Context) (done bool, err error) {
				return false, nil
			},
			expectedErr: context.Canceled,
		},
		{
			name: "when condition is done, exit early",
			steps: []time.Duration{
				time.Duration(0),
				time.Duration(0),
				time.Duration(0),
			},
			finalCondition: func(ctx context.Context) (done bool, err error) {
				return true, nil
			},
			expectedErr: nil,
		},
		{
			name: "when condition returns error, exit early",
			steps: []time.Duration{
				time.Duration(0),
				time.Duration(0),
				time.Duration(0),
				time.Duration(0),
				time.Duration(0),
			},
			finalCondition: func(ctx context.Context) (done bool, err error) {
				return false, errors.New("error from condition")
			},
			expectedErr: errors.New("error from condition"),
		},
		{
			name: "when condition panics, cover and exit",
			steps: []time.Duration{
				time.Duration(0),
			},
			finalCondition: func(ctx context.Context) (done bool, err error) {
				panic(errors.New("panic error"))
			},
			expectedErr: errors.New("panic error"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testContext, cancel := context.WithCancel(context.Background())
			backoff := &MockStepper{
				steps: tt.steps,
			}
			actualConditionCalls := 0

			err := WithContext(testContext, backoff, func(ctx context.Context) (done bool, err error) {
				actualConditionCalls++

				if backoff.currentStep >= (len(backoff.steps) - 1) {
					cancel()
					return tt.finalCondition(ctx)
				}

				return false, nil
			})
			require.Equal(t, tt.expectedErr, err)
			require.Equal(t, len(backoff.steps), actualConditionCalls)
		})
	}

	t.Run("does not invoke any functions when run with a cancelled context", func(t *testing.T) {
		testContext, cancel := context.WithCancel(context.Background())
		cancel()

		stepper := &MockStepper{}

		conditionCalls := 0
		condition := func(context.Context) (done bool, err error) {
			conditionCalls++
			return false, nil
		}

		err := WithContext(testContext, stepper, condition)
		require.Equal(t, context.Canceled, err)
		require.Equal(t, 0, conditionCalls)
		require.Equal(t, 0, stepper.currentStep)
	})
}
