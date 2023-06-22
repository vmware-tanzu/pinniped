package resolvedprovider

import (
	"go.pinniped.dev/internal/idtransform"
	"go.pinniped.dev/internal/oidc/provider/upstreamprovider"
	"go.pinniped.dev/internal/psession"
)

// FederationDomainResolvedOIDCIdentityProvider represents a FederationDomainIdentityProvider which has
// been resolved dynamically based on the currently loaded IDP CRs to include the provider.UpstreamOIDCIdentityProviderI
// and other metadata about the provider.
type FederationDomainResolvedOIDCIdentityProvider struct {
	DisplayName         string
	Provider            upstreamprovider.UpstreamOIDCIdentityProviderI
	SessionProviderType psession.ProviderType
	Transforms          *idtransform.TransformationPipeline
}

// FederationDomainResolvedLDAPIdentityProvider represents a FederationDomainIdentityProvider which has
// been resolved dynamically based on the currently loaded IDP CRs to include the provider.UpstreamLDAPIdentityProviderI
// and other metadata about the provider.
type FederationDomainResolvedLDAPIdentityProvider struct {
	DisplayName         string
	Provider            upstreamprovider.UpstreamLDAPIdentityProviderI
	SessionProviderType psession.ProviderType
	Transforms          *idtransform.TransformationPipeline
}
