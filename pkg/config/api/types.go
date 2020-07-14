/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package api

// Config contains knobs to setup an instance of placeholder-name.
type Config struct {
	WebhookConfig WebhookConfigSpec `json:"webhook"`
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
