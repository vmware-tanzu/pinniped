package integration

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetNodes(t *testing.T) {
	err := exec.Command("kubectl", "get", "nodes").Run()
	require.NoError(t, err)
}
