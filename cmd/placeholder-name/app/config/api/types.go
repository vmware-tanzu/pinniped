package api

// Config contains the knobs that can be used to setup an instance of
// placeholder-name.
// TODO(akeesler): k8s generation thingys
type Config struct {
	// Preferred input version of this configuration type.
	ApiVersion string `yaml:"apiVersion"`

	// WebhookURL contains the URL of the webhook that placeholder-name will use
	// to validate external credentials.
	WebhookURL string `yaml:"webhookURL"`

	// WebhookCABundlePath is the path to the CA bundle that placeholder-name will
	// use to validate TLS connections to the WebhookURL.
	WebhookCABundlePath string `yaml:"webhookCABundlePath"`
}
