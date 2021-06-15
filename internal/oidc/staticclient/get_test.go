package staticclient

import (
	"testing"

	"github.com/ory/fosite"
	"github.com/stretchr/testify/require"
)

func TestGet(t *testing.T) {
	t.Run("not found", func(t *testing.T) {
		got, err := Get("does-not-exist")
		require.Error(t, err)
		require.Nil(t, got)
		rfcErr := fosite.ErrorToRFC6749Error(err)
		require.NotNil(t, rfcErr)
		require.Equal(t, rfcErr.CodeField, 404)
		require.Equal(t, rfcErr.GetDescription(), "no such client")
	})

	t.Run("pinniped CLI", func(t *testing.T) {
		got, err := Get("pinniped-cli")
		require.NoError(t, err)
		require.NotNil(t, got)
		require.IsType(t, &PinnipedCLI{}, got)
	})
}
