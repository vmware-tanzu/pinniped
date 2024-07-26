package tlsconfigutil

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/certauthority"
)

func TestCABundleIsEqual(t *testing.T) {
	testCA, err := certauthority.New("Test CA", 1*time.Hour)
	require.NoError(t, err)
	certPool := x509.NewCertPool()
	require.True(t, certPool.AppendCertsFromPEM(testCA.Bundle()))

	tests := []struct {
		name     string
		left     *CABundle
		right    *CABundle
		expected bool
	}{
		{
			name:     "should return equal when left and right are nil",
			left:     nil,
			right:    nil,
			expected: true,
		},
		{
			name:     "should return not equal when left is nil and right is not",
			left:     nil,
			right:    &CABundle{},
			expected: false,
		},
		{
			name:     "should return not equal when right is nil and left is not",
			left:     &CABundle{},
			right:    nil,
			expected: false,
		},
		{
			name: "should return equal when both left and right have same CA certificate bytes",
			left: &CABundle{
				caBundle: testCA.Bundle(),
				certPool: certPool,
			},
			right: &CABundle{
				caBundle: testCA.Bundle(),
				certPool: certPool,
			},
			expected: true,
		},
		{
			name: "should return not equal when both left and right do not have same CA certificate bytes",
			left: &CABundle{
				caBundle: testCA.Bundle(),
				certPool: certPool,
			},
			right: &CABundle{
				caBundle: []byte("something that is not a cert"),
				certPool: nil,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			actual := tt.left.IsEqual(tt.right)
			require.Equal(t, tt.expected, actual)
		})
	}
}
