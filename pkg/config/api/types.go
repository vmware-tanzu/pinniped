/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package api

// Config contains knobs to setup an instance of placeholder-name.
type Config struct {
	WebhookConfig   WebhookConfigSpec   `json:"webhook"`
	DiscoveryConfig DiscoveryConfigSpec `json:"discovery"`
}

// WebhookConfig contains configuration knobs specific to placeholder-name's use
// of a webhook for token validation.
type WebhookConfigSpec struct {
	// URL contains the URL of the webhook that placeholder-name will use
	// to validate external credentials.
	URL string `json:"url"`

	// CABundle contains PEM-encoded certificate authority certificates used
	// to validate TLS connections to the WebhookURL.
	CABundle []byte `json:"caBundle"`
}

// DiscoveryConfigSpec contains configuration knobs specific to
// placeholder-name's publishing of discovery information. These values can be
// viewed as overrides, i.e., if these are set, then placeholder-name will
// publish these values in its discovery document instead of the ones it finds.
type DiscoveryConfigSpec struct {
	// URL contains the URL at which placeholder-name can be contacted.
	URL *string `json:"url,omitempty"`
}
