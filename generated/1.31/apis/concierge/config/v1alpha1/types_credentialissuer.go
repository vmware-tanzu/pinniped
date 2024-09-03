// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// StrategyType enumerates a type of "strategy" used to implement credential access on a cluster.
// +kubebuilder:validation:Enum=KubeClusterSigningCertificate;ImpersonationProxy
type StrategyType string

// FrontendType enumerates a type of "frontend" used to provide access to users of a cluster.
// +kubebuilder:validation:Enum=TokenCredentialRequestAPI;ImpersonationProxy
type FrontendType string

// StrategyStatus enumerates whether a strategy is working on a cluster.
// +kubebuilder:validation:Enum=Success;Error
type StrategyStatus string

// StrategyReason enumerates the detailed reason why a strategy is in a particular status.
// +kubebuilder:validation:Enum=Listening;Pending;Disabled;ErrorDuringSetup;CouldNotFetchKey;CouldNotGetClusterInfo;FetchedKey
type StrategyReason string

const (
	KubeClusterSigningCertificateStrategyType = StrategyType("KubeClusterSigningCertificate")
	ImpersonationProxyStrategyType            = StrategyType("ImpersonationProxy")

	TokenCredentialRequestAPIFrontendType = FrontendType("TokenCredentialRequestAPI")
	ImpersonationProxyFrontendType        = FrontendType("ImpersonationProxy")

	SuccessStrategyStatus = StrategyStatus("Success")
	ErrorStrategyStatus   = StrategyStatus("Error")

	ListeningStrategyReason              = StrategyReason("Listening")
	PendingStrategyReason                = StrategyReason("Pending")
	DisabledStrategyReason               = StrategyReason("Disabled")
	ErrorDuringSetupStrategyReason       = StrategyReason("ErrorDuringSetup")
	CouldNotFetchKeyStrategyReason       = StrategyReason("CouldNotFetchKey")
	CouldNotGetClusterInfoStrategyReason = StrategyReason("CouldNotGetClusterInfo")
	FetchedKeyStrategyReason             = StrategyReason("FetchedKey")
)

// CredentialIssuerSpec describes the intended configuration of the Concierge.
type CredentialIssuerSpec struct {
	// ImpersonationProxy describes the intended configuration of the Concierge impersonation proxy.
	ImpersonationProxy *ImpersonationProxySpec `json:"impersonationProxy"`
}

// ImpersonationProxyMode enumerates the configuration modes for the impersonation proxy.
// Allowed values are "auto", "enabled", or "disabled".
//
// +kubebuilder:validation:Enum=auto;enabled;disabled
type ImpersonationProxyMode string

const (
	// ImpersonationProxyModeDisabled explicitly disables the impersonation proxy.
	ImpersonationProxyModeDisabled = ImpersonationProxyMode("disabled")

	// ImpersonationProxyModeEnabled explicitly enables the impersonation proxy.
	ImpersonationProxyModeEnabled = ImpersonationProxyMode("enabled")

	// ImpersonationProxyModeAuto enables or disables the impersonation proxy based upon the cluster in which it is running.
	ImpersonationProxyModeAuto = ImpersonationProxyMode("auto")
)

// ImpersonationProxyServiceType enumerates the types of service that can be provisioned for the impersonation proxy.
// Allowed values are "LoadBalancer", "ClusterIP", or "None".
//
// +kubebuilder:validation:Enum=LoadBalancer;ClusterIP;None
type ImpersonationProxyServiceType string

const (
	// ImpersonationProxyServiceTypeLoadBalancer provisions a service of type LoadBalancer.
	ImpersonationProxyServiceTypeLoadBalancer = ImpersonationProxyServiceType("LoadBalancer")

	// ImpersonationProxyServiceTypeClusterIP provisions a service of type ClusterIP.
	ImpersonationProxyServiceTypeClusterIP = ImpersonationProxyServiceType("ClusterIP")

	// ImpersonationProxyServiceTypeNone does not automatically provision any service.
	ImpersonationProxyServiceTypeNone = ImpersonationProxyServiceType("None")
)

// ImpersonationProxyTLSSpec contains information about how the Concierge impersonation proxy should
// serve TLS.
//
// If CertificateAuthorityData is not provided, the Concierge impersonation proxy will check the secret
// for a field called "ca.crt", which will be used as the CertificateAuthorityData.
//
// If neither CertificateAuthorityData nor ca.crt is provided, no CA bundle will be advertised for
// the impersonation proxy endpoint.
type ImpersonationProxyTLSSpec struct {
	// X.509 Certificate Authority (base64-encoded PEM bundle).
	// Used to advertise the CA bundle for the impersonation proxy endpoint.
	//
	// +optional
	CertificateAuthorityData string `json:"certificateAuthorityData,omitempty"`

	// SecretName is the name of a Secret in the same namespace, of type `kubernetes.io/tls`, which contains
	// the TLS serving certificate for the Concierge impersonation proxy endpoint.
	//
	// +kubebuilder:validation:MinLength=1
	SecretName string `json:"secretName,omitempty"`
}

// ImpersonationProxySpec describes the intended configuration of the Concierge impersonation proxy.
type ImpersonationProxySpec struct {
	// Mode configures whether the impersonation proxy should be started:
	// - "disabled" explicitly disables the impersonation proxy. This is the default.
	// - "enabled" explicitly enables the impersonation proxy.
	// - "auto" enables or disables the impersonation proxy based upon the cluster in which it is running.
	Mode ImpersonationProxyMode `json:"mode"`

	// Service describes the configuration of the Service provisioned to expose the impersonation proxy to clients.
	//
	// +kubebuilder:default:={"type": "LoadBalancer"}
	Service ImpersonationProxyServiceSpec `json:"service"`

	// ExternalEndpoint describes the HTTPS endpoint where the proxy will be exposed. If not set, the proxy will
	// be served using the external name of the LoadBalancer service or the cluster service DNS name.
	//
	// This field must be non-empty when spec.impersonationProxy.service.type is "None".
	//
	// +optional
	ExternalEndpoint string `json:"externalEndpoint,omitempty"`

	// TLS contains information about how the Concierge impersonation proxy should serve TLS.
	//
	// If this field is empty, the impersonation proxy will generate its own TLS certificate.
	//
	// +optional
	TLS *ImpersonationProxyTLSSpec `json:"tls,omitempty"`
}

// ImpersonationProxyServiceSpec describes how the Concierge should provision a Service to expose the impersonation proxy.
type ImpersonationProxyServiceSpec struct {
	// Type specifies the type of Service to provision for the impersonation proxy.
	//
	// If the type is "None", then the "spec.impersonationProxy.externalEndpoint" field must be set to a non-empty
	// value so that the Concierge can properly advertise the endpoint in the CredentialIssuer's status.
	//
	// +kubebuilder:default:="LoadBalancer"
	Type ImpersonationProxyServiceType `json:"type,omitempty"`

	// LoadBalancerIP specifies the IP address to set in the spec.loadBalancerIP field of the provisioned Service.
	// This is not supported on all cloud providers.
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	// +optional
	LoadBalancerIP string `json:"loadBalancerIP,omitempty"`

	// Annotations specifies zero or more key/value pairs to set as annotations on the provisioned Service.
	//
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// CredentialIssuerStatus describes the status of the Concierge.
type CredentialIssuerStatus struct {
	// List of integration strategies that were attempted by Pinniped.
	Strategies []CredentialIssuerStrategy `json:"strategies"`

	// Information needed to form a valid Pinniped-based kubeconfig using this credential issuer.
	// This field is deprecated and will be removed in a future version.
	// +optional
	KubeConfigInfo *CredentialIssuerKubeConfigInfo `json:"kubeConfigInfo,omitempty"`
}

// CredentialIssuerKubeConfigInfo provides the information needed to form a valid Pinniped-based kubeconfig using this credential issuer.
// This type is deprecated and will be removed in a future version.
type CredentialIssuerKubeConfigInfo struct {
	// The K8s API server URL.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^https://|^http://`
	Server string `json:"server"`

	// The K8s API server CA bundle.
	// +kubebuilder:validation:MinLength=1
	CertificateAuthorityData string `json:"certificateAuthorityData"`
}

// CredentialIssuerStrategy describes the status of an integration strategy that was attempted by Pinniped.
type CredentialIssuerStrategy struct {
	// Type of integration attempted.
	Type StrategyType `json:"type"`

	// Status of the attempted integration strategy.
	Status StrategyStatus `json:"status"`

	// Reason for the current status.
	Reason StrategyReason `json:"reason"`

	// Human-readable description of the current status.
	// +kubebuilder:validation:MinLength=1
	Message string `json:"message"`

	// When the status was last checked.
	LastUpdateTime metav1.Time `json:"lastUpdateTime"`

	// Frontend describes how clients can connect using this strategy.
	Frontend *CredentialIssuerFrontend `json:"frontend,omitempty"`
}

// CredentialIssuerFrontend describes how to connect using a particular integration strategy.
type CredentialIssuerFrontend struct {
	// Type describes which frontend mechanism clients can use with a strategy.
	Type FrontendType `json:"type"`

	// TokenCredentialRequestAPIInfo describes the parameters for the TokenCredentialRequest API on this Concierge.
	// This field is only set when Type is "TokenCredentialRequestAPI".
	TokenCredentialRequestAPIInfo *TokenCredentialRequestAPIInfo `json:"tokenCredentialRequestInfo,omitempty"`

	// ImpersonationProxyInfo describes the parameters for the impersonation proxy on this Concierge.
	// This field is only set when Type is "ImpersonationProxy".
	ImpersonationProxyInfo *ImpersonationProxyInfo `json:"impersonationProxyInfo,omitempty"`
}

// TokenCredentialRequestAPIInfo describes the parameters for the TokenCredentialRequest API on this Concierge.
type TokenCredentialRequestAPIInfo struct {
	// Server is the Kubernetes API server URL.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^https://|^http://`
	Server string `json:"server"`

	// CertificateAuthorityData is the base64-encoded Kubernetes API server CA bundle.
	// +kubebuilder:validation:MinLength=1
	CertificateAuthorityData string `json:"certificateAuthorityData"`
}

// ImpersonationProxyInfo describes the parameters for the impersonation proxy on this Concierge.
type ImpersonationProxyInfo struct {
	// Endpoint is the HTTPS endpoint of the impersonation proxy.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^https://`
	Endpoint string `json:"endpoint"`

	// CertificateAuthorityData is the base64-encoded PEM CA bundle of the impersonation proxy.
	// +kubebuilder:validation:MinLength=1
	CertificateAuthorityData string `json:"certificateAuthorityData"`
}

// CredentialIssuer describes the configuration and status of the Pinniped Concierge credential issuer.
// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories=pinniped,scope=Cluster
// +kubebuilder:printcolumn:name="ProxyMode",type=string,JSONPath=`.spec.impersonationProxy.mode`
// +kubebuilder:printcolumn:name="DefaultStrategy",type=string,JSONPath=`.status.strategies[?(@.status == "Success")].type`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:subresource:status
type CredentialIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec describes the intended configuration of the Concierge.
	//
	// +optional
	Spec CredentialIssuerSpec `json:"spec"`

	// CredentialIssuerStatus describes the status of the Concierge.
	//
	// +optional
	Status CredentialIssuerStatus `json:"status"`
}

// CredentialIssuerList is a list of CredentialIssuer objects.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type CredentialIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []CredentialIssuer `json:"items"`
}
