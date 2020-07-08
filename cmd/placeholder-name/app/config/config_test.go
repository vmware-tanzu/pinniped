package config

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/suzerain-io/placeholder-name/cmd/placeholder-name/app/config/api"
)

func TestFromPath(t *testing.T) {
	expect := require.New(t)

	file, err := ioutil.TempFile("", "placeholder-name-config-test")
	expect.NoError(err)
	defer os.Remove(file.Name())
	t.Log(file.Name())

	_, err = file.WriteString(`---
apiVersion: v1alpha1
webhookURL: https://tuna.com/fish?marlin
webhookCABundlePath: ../tuna/fish/marlin.yaml
`)
	expect.NoError(err)

	config, err := FromPath(file.Name())
	expect.NoError(err)
	expect.Equal(config, &api.Config{
		ApiVersion:          "v1alpha1",
		WebhookURL:          "https://tuna.com/fish?marlin",
		WebhookCABundlePath: "../tuna/fish/marlin.yaml",
	})
}
