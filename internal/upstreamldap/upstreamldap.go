// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package upstreamldap implements an abstraction of upstream LDAP IDP interactions.
package upstreamldap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/utils/trace"

	"go.pinniped.dev/internal/authenticators"
	"go.pinniped.dev/internal/endpointaddr"
	"go.pinniped.dev/internal/oidc/downstreamsession"
	"go.pinniped.dev/internal/oidc/provider"
	"go.pinniped.dev/internal/plog"
)

const (
	ldapsScheme                             = "ldaps"
	distinguishedNameAttributeName          = "dn"
	searchFilterInterpolationLocationMarker = "{}"
	groupSearchPageSize                     = uint32(250)
	defaultLDAPPort                         = uint16(389)
	defaultLDAPSPort                        = uint16(636)
	sAMAccountNameAttribute                 = "sAMAccountName"
)

// Conn abstracts the upstream LDAP communication protocol (mostly for testing).
type Conn interface {
	Bind(username, password string) error

	Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error)

	SearchWithPaging(searchRequest *ldap.SearchRequest, pagingSize uint32) (*ldap.SearchResult, error)

	Close()
}

// Our Conn type is subset of the ldap.Client interface, which is implemented by ldap.Conn.
var _ Conn = &ldap.Conn{}

// LDAPDialer is a factory of Conn, and the resulting Conn can then be used to interact with an upstream LDAP IDP.
type LDAPDialer interface {
	Dial(ctx context.Context, addr endpointaddr.HostPort) (Conn, error)
}

// LDAPDialerFunc makes it easy to use a func as an LDAPDialer.
type LDAPDialerFunc func(ctx context.Context, addr endpointaddr.HostPort) (Conn, error)

var _ LDAPDialer = LDAPDialerFunc(nil)

func (f LDAPDialerFunc) Dial(ctx context.Context, addr endpointaddr.HostPort) (Conn, error) {
	return f(ctx, addr)
}

type LDAPConnectionProtocol string

const (
	StartTLS = LDAPConnectionProtocol("StartTLS")
	TLS      = LDAPConnectionProtocol("TLS")
)

// ProviderConfig includes all of the settings for connection and searching for users and groups in
// the upstream LDAP IDP. It also provides methods for testing the connection and performing logins.
// The nested structs are not pointer fields to enable deep copy on function params and return values.
type ProviderConfig struct {
	// Name is the unique name of this upstream LDAP IDP.
	Name string

	// ResourceUID is the Kubernetes resource UID of this identity provider.
	ResourceUID types.UID

	// Host is the hostname or "hostname:port" of the LDAP server. When the port is not specified,
	// the default LDAP port will be used.
	Host string

	// ConnectionProtocol determines how to establish the connection to the server. Either StartTLS or TLS.
	ConnectionProtocol LDAPConnectionProtocol

	// PEM-encoded CA cert bundle to trust when connecting to the LDAP server. Can be nil.
	CABundle []byte

	// BindUsername is the username to use when performing a bind with the upstream LDAP IDP.
	BindUsername string

	// BindPassword is the password to use when performing a bind with the upstream LDAP IDP.
	BindPassword string

	// UserSearch contains information about how to search for users in the upstream LDAP IDP.
	UserSearch UserSearchConfig

	// GroupSearch contains information about how to search for group membership in the upstream LDAP IDP.
	GroupSearch GroupSearchConfig

	// Dialer exists to enable testing. When nil, will use a default appropriate for production use.
	Dialer LDAPDialer

	// UIDAttributeParsingOverrides are mappings between an attribute name and a way to parse it as a UID when
	// it comes out of LDAP.
	UIDAttributeParsingOverrides map[string]func(*ldap.Entry) (string, error)

	// GroupNameMappingOverrides are the mappings between an attribute name and a way to parse it as a group
	// name when it comes out of LDAP.
	GroupAttributeParsingOverrides map[string]func(*ldap.Entry) (string, error)
}

// UserSearchConfig contains information about how to search for users in the upstream LDAP IDP.
type UserSearchConfig struct {
	// Base is the base DN to use for the user search in the upstream LDAP IDP.
	Base string

	// Filter is the filter to use for the user search in the upstream LDAP IDP.
	Filter string

	// UsernameAttribute is the attribute in the LDAP entry from which the username should be
	// retrieved.
	UsernameAttribute string

	// UIDAttribute is the attribute in the LDAP entry from which the user's unique ID should be
	// retrieved.
	UIDAttribute string
}

// GroupSearchConfig contains information about how to search for group membership for users in the upstream LDAP IDP.
type GroupSearchConfig struct {
	// Base is the base DN to use for the group search in the upstream LDAP IDP. Empty means to skip group search
	// entirely, in which case authenticated users will not belong to any groups from the upstream LDAP IDP.
	Base string

	// Filter is the filter to use for the group search in the upstream LDAP IDP. Empty means to use `member={}`.
	Filter string

	// GroupNameAttribute is the attribute in the LDAP group entry from which the group name should be
	// retrieved. Empty means to use 'cn'.
	GroupNameAttribute string
}

type Provider struct {
	c ProviderConfig
}

var _ provider.UpstreamLDAPIdentityProviderI = &Provider{}
var _ authenticators.UserAuthenticator = &Provider{}

// Create a Provider. The config is not a pointer to ensure that a copy of the config is created,
// making the resulting Provider use an effectively read-only configuration.
func New(config ProviderConfig) *Provider {
	return &Provider{c: config}
}

// A reader for the config. Returns a copy of the config to keep the underlying config read-only.
func (p *Provider) GetConfig() ProviderConfig {
	return p.c
}

func (p *Provider) PerformRefresh(ctx context.Context, userDN string, expectedUsername string, expectedSubject string) error {
	t := trace.FromContext(ctx).Nest("slow ldap refresh attempt", trace.Field{Key: "providerName", Value: p.GetName()})
	defer t.LogIfLong(500 * time.Millisecond) // to help users debug slow LDAP searches
	search := p.refreshUserSearchRequest(userDN)

	conn, err := p.dial(ctx)
	if err != nil {
		p.traceRefreshFailure(t, err)
		return fmt.Errorf(`error dialing host "%s": %w`, p.c.Host, err)
	}
	defer conn.Close()

	err = conn.Bind(p.c.BindUsername, p.c.BindPassword)
	if err != nil {
		p.traceRefreshFailure(t, err)
		return fmt.Errorf(`error binding as "%s" before user search: %w`, p.c.BindUsername, err)
	}

	searchResult, err := conn.Search(search)

	if err != nil {
		p.traceRefreshFailure(t, err)
		return fmt.Errorf(`error searching for user "%s": %w`, userDN, err)
	}

	// if any more or less than one entry, error.
	// we don't need to worry about logging this because we know it's a dn.
	if len(searchResult.Entries) != 1 {
		return fmt.Errorf(`searching for user "%s" resulted in %d search results, but expected 1 result`,
			userDN, len(searchResult.Entries),
		)
	}

	userEntry := searchResult.Entries[0]
	if len(userEntry.DN) == 0 {
		return fmt.Errorf(`searching for user with original DN "%s" resulted in search result without DN`, userDN)
	}

	newUsername, err := p.getSearchResultAttributeValue(p.c.UserSearch.UsernameAttribute, userEntry, userDN)
	if err != nil {
		return err // TODO test having no values or more than one maybe
	}
	if newUsername != expectedUsername {
		return fmt.Errorf(`searching for user "%s" returned a different username than the previous value. expected: "%s", actual: "%s"`,
			userDN, expectedUsername, newUsername,
		)
	}

	newUID, err := p.getSearchResultAttributeRawValueEncoded(p.c.UserSearch.UIDAttribute, userEntry, userDN)
	if err != nil {
		return err // TODO test
	}
	newSubject := downstreamsession.DownstreamLDAPSubject(newUID, *p.GetURL())
	if newSubject != expectedSubject {
		return fmt.Errorf(`searching for user "%s" produced a different subject than the previous value. expected: "%s", actual: "%s"`, userDN, expectedSubject, newSubject)
	}

	// do nothing. if we got exactly one search result back then that means the user
	// still exists.
	return nil
}

func (p *Provider) dial(ctx context.Context) (Conn, error) {
	tlsAddr, err := endpointaddr.Parse(p.c.Host, defaultLDAPSPort)
	if err != nil {
		return nil, ldap.NewError(ldap.ErrorNetwork, err)
	}

	startTLSAddr, err := endpointaddr.Parse(p.c.Host, defaultLDAPPort)
	if err != nil {
		return nil, ldap.NewError(ldap.ErrorNetwork, err)
	}

	// Choose how and where to dial based on TLS vs. StartTLS config option.
	var dialFunc LDAPDialerFunc
	var addr endpointaddr.HostPort
	switch {
	case p.c.ConnectionProtocol == TLS:
		dialFunc = p.dialTLS
		addr = tlsAddr
	case p.c.ConnectionProtocol == StartTLS:
		dialFunc = p.dialStartTLS
		addr = startTLSAddr
	default:
		return nil, ldap.NewError(ldap.ErrorNetwork, fmt.Errorf("did not specify valid ConnectionProtocol"))
	}

	// Override the real dialer for testing purposes sometimes.
	if p.c.Dialer != nil {
		dialFunc = p.c.Dialer.Dial
	}

	return dialFunc(ctx, addr)
}

// dialTLS is a default implementation of the Dialer, used when Dialer is nil and ConnectionProtocol is TLS.
// Unfortunately, the go-ldap library does not seem to support dialing with a context.Context,
// so we implement it ourselves, heavily inspired by ldap.DialURL.
func (p *Provider) dialTLS(ctx context.Context, addr endpointaddr.HostPort) (Conn, error) {
	tlsConfig, err := p.tlsConfig()
	if err != nil {
		return nil, ldap.NewError(ldap.ErrorNetwork, err)
	}

	dialer := &tls.Dialer{NetDialer: netDialer(), Config: tlsConfig}
	c, err := dialer.DialContext(ctx, "tcp", addr.Endpoint())
	if err != nil {
		return nil, ldap.NewError(ldap.ErrorNetwork, err)
	}

	conn := ldap.NewConn(c, true)
	conn.Start()
	return conn, nil
}

// dialTLS is a default implementation of the Dialer, used when Dialer is nil and ConnectionProtocol is StartTLS.
// Unfortunately, the go-ldap library does not seem to support dialing with a context.Context,
// so we implement it ourselves, heavily inspired by ldap.DialURL.
func (p *Provider) dialStartTLS(ctx context.Context, addr endpointaddr.HostPort) (Conn, error) {
	tlsConfig, err := p.tlsConfig()
	if err != nil {
		return nil, ldap.NewError(ldap.ErrorNetwork, err)
	}

	// Unfortunately, this seems to be required for StartTLS, even though it is not needed for regular TLS.
	tlsConfig.ServerName = addr.Host

	c, err := netDialer().DialContext(ctx, "tcp", addr.Endpoint())
	if err != nil {
		return nil, ldap.NewError(ldap.ErrorNetwork, err)
	}

	conn := ldap.NewConn(c, false)
	conn.Start()
	err = conn.StartTLS(tlsConfig)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func netDialer() *net.Dialer {
	return &net.Dialer{Timeout: time.Minute}
}

func (p *Provider) tlsConfig() (*tls.Config, error) {
	var rootCAs *x509.CertPool
	if p.c.CABundle != nil {
		rootCAs = x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(p.c.CABundle) {
			return nil, fmt.Errorf("could not parse CA bundle")
		}
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: rootCAs}, nil
}

// A name for this upstream provider.
func (p *Provider) GetName() string {
	return p.c.Name
}

func (p *Provider) GetResourceUID() types.UID {
	return p.c.ResourceUID
}

// Return a URL which uniquely identifies this LDAP provider, e.g. "ldaps://host.example.com:1234?base=user-search-base".
// This URL is not used for connecting to the provider, but rather is used for creating a globally unique user
// identifier by being combined with the user's UID, since user UIDs are only unique within one provider.
func (p *Provider) GetURL() *url.URL {
	u := &url.URL{Scheme: ldapsScheme, Host: p.c.Host}
	q := u.Query()
	q.Set("base", p.c.UserSearch.Base)
	u.RawQuery = q.Encode()
	return u
}

// TestConnection provides a method for testing the connection and bind settings. It performs a dial and bind
// and returns any errors that we encountered.
func (p *Provider) TestConnection(ctx context.Context) error {
	err := p.validateConfig()
	if err != nil {
		return err
	}

	conn, err := p.dial(ctx)
	if err != nil {
		return fmt.Errorf(`error dialing host "%s": %w`, p.c.Host, err)
	}
	defer conn.Close()

	err = conn.Bind(p.c.BindUsername, p.c.BindPassword)
	if err != nil {
		return fmt.Errorf(`error binding as "%s": %w`, p.c.BindUsername, err)
	}

	return nil
}

// DryRunAuthenticateUser provides a method for testing all of the Provider settings in a kind of dry run of
// authentication for a given end user's username. It runs the same logic as AuthenticateUser except it does
// not bind as that user, so it does not test their password. It returns the same values that a real call to
// AuthenticateUser with the correct password would return.
func (p *Provider) DryRunAuthenticateUser(ctx context.Context, username string) (*authenticator.Response, bool, error) {
	endUserBindFunc := func(conn Conn, foundUserDN string) error {
		// Act as if the end user bind always succeeds.
		return nil
	}
	return p.authenticateUserImpl(ctx, username, endUserBindFunc)
}

// Authenticate an end user and return their mapped username, groups, and UID. Implements authenticators.UserAuthenticator.
func (p *Provider) AuthenticateUser(ctx context.Context, username, password string) (*authenticator.Response, bool, error) {
	endUserBindFunc := func(conn Conn, foundUserDN string) error {
		return conn.Bind(foundUserDN, password)
	}
	return p.authenticateUserImpl(ctx, username, endUserBindFunc)
}

func (p *Provider) authenticateUserImpl(ctx context.Context, username string, bindFunc func(conn Conn, foundUserDN string) error) (*authenticator.Response, bool, error) {
	t := trace.FromContext(ctx).Nest("slow ldap authenticate user attempt", trace.Field{Key: "providerName", Value: p.GetName()})
	defer t.LogIfLong(500 * time.Millisecond) // to help users debug slow LDAP searches

	err := p.validateConfig()
	if err != nil {
		p.traceAuthFailure(t, err)
		return nil, false, err
	}

	if len(username) == 0 {
		// Empty passwords are already handled by go-ldap.
		p.traceAuthFailure(t, fmt.Errorf("empty username"))
		return nil, false, nil
	}

	conn, err := p.dial(ctx)
	if err != nil {
		p.traceAuthFailure(t, err)
		return nil, false, fmt.Errorf(`error dialing host "%s": %w`, p.c.Host, err)
	}
	defer conn.Close()

	err = conn.Bind(p.c.BindUsername, p.c.BindPassword)
	if err != nil {
		p.traceAuthFailure(t, err)
		return nil, false, fmt.Errorf(`error binding as "%s" before user search: %w`, p.c.BindUsername, err)
	}

	mappedUsername, mappedUID, mappedGroupNames, userDN, err := p.searchAndBindUser(conn, username, bindFunc)
	if err != nil {
		p.traceAuthFailure(t, err)
		return nil, false, err
	}
	if len(mappedUsername) == 0 || len(mappedUID) == 0 {
		// Couldn't find the username or couldn't bind using the password.
		p.traceAuthFailure(t, fmt.Errorf("bad username or password"))
		return nil, false, nil
	}

	response := &authenticator.Response{
		User: &user.DefaultInfo{
			Name:   mappedUsername,
			UID:    mappedUID,
			Groups: mappedGroupNames,
			Extra:  map[string][]string{"userDN": {userDN}},
		},
	}
	p.traceAuthSuccess(t)
	return response, true, nil
}

func (p *Provider) searchGroupsForUserDN(conn Conn, userDN string) ([]string, error) {
	searchResult, err := conn.SearchWithPaging(p.groupSearchRequest(userDN), groupSearchPageSize)
	if err != nil {
		return nil, fmt.Errorf(`error searching for group memberships for user with DN %q: %w`, userDN, err)
	}

	groupAttributeName := p.c.GroupSearch.GroupNameAttribute
	if len(groupAttributeName) == 0 {
		groupAttributeName = distinguishedNameAttributeName
	}

	groups := []string{}
entries:
	for _, groupEntry := range searchResult.Entries {
		if len(groupEntry.DN) == 0 {
			return nil, fmt.Errorf(`searching for group memberships for user with DN %q resulted in search result without DN`, userDN)
		}
		if overrideFunc := p.c.GroupAttributeParsingOverrides[groupAttributeName]; overrideFunc != nil {
			overrideGroupName, err := overrideFunc(groupEntry)
			if err != nil {
				return nil, fmt.Errorf("error finding groups for user %s: %w", userDN, err)
			}
			groups = append(groups, overrideGroupName)
			continue entries
		}
		// if none of the overrides matched, use the default behavior (no mapping)
		mappedGroupName, err := p.getSearchResultAttributeValue(groupAttributeName, groupEntry, userDN)
		if err != nil {
			return nil, fmt.Errorf(`error searching for group memberships for user with DN %q: %w`, userDN, err)
		}
		groups = append(groups, mappedGroupName)
	}

	return groups, nil
}

func (p *Provider) validateConfig() error {
	if p.c.UserSearch.UsernameAttribute == distinguishedNameAttributeName && len(p.c.UserSearch.Filter) == 0 {
		// LDAP search filters do not allow searching by DN, so we would have no reasonable default for Filter.
		return fmt.Errorf(`must specify UserSearch Filter when UserSearch UsernameAttribute is "dn"`)
	}
	return nil
}

func (p *Provider) SearchForDefaultNamingContext(ctx context.Context) (string, error) {
	t := trace.FromContext(ctx).Nest("slow ldap attempt when searching for default naming context", trace.Field{Key: "providerName", Value: p.GetName()})
	defer t.LogIfLong(500 * time.Millisecond) // to help users debug slow LDAP searches

	conn, err := p.dial(ctx)
	if err != nil {
		p.traceSearchBaseDiscoveryFailure(t, err)
		return "", fmt.Errorf(`error dialing host "%s": %w`, p.c.Host, err)
	}
	defer conn.Close()

	err = conn.Bind(p.c.BindUsername, p.c.BindPassword)
	if err != nil {
		p.traceSearchBaseDiscoveryFailure(t, err)
		return "", fmt.Errorf(`error binding as "%s" before querying for defaultNamingContext: %w`, p.c.BindUsername, err)
	}

	searchResult, err := conn.Search(p.defaultNamingContextRequest())
	if err != nil {
		return "", fmt.Errorf(`error querying RootDSE for defaultNamingContext: %w`, err)
	}

	if len(searchResult.Entries) != 1 {
		return "", fmt.Errorf(`error querying RootDSE for defaultNamingContext: expected to find 1 entry but found %d`, len(searchResult.Entries))
	}
	searchBase := searchResult.Entries[0].GetAttributeValue("defaultNamingContext")
	if searchBase == "" {
		// if we get an empty search base back, treat it like an error. Otherwise we might make too broad of a search.
		return "", fmt.Errorf(`error querying RootDSE for defaultNamingContext: empty search base DN found`)
	}
	return searchBase, nil
}

func (p *Provider) searchAndBindUser(conn Conn, username string, bindFunc func(conn Conn, foundUserDN string) error) (string, string, []string, string, error) {
	searchResult, err := conn.Search(p.userSearchRequest(username))
	if err != nil {
		plog.All(`error searching for user`,
			"upstreamName", p.GetName(),
			"username", username,
			"err", err,
		)
		return "", "", nil, "", fmt.Errorf(`error searching for user: %w`, err)
	}
	if len(searchResult.Entries) == 0 {
		if plog.Enabled(plog.LevelAll) {
			plog.All("error finding user: user not found (if this username is valid, please check the user search configuration)",
				"upstreamName", p.GetName(),
				"username", username,
			)
		} else {
			plog.Debug("error finding user: user not found (cowardly avoiding printing username because log level is not 'all')", "upstreamName", p.GetName())
		}
		return "", "", nil, "", nil
	}

	// At this point, we have matched at least one entry, so we can be confident that the username is not actually
	// someone's password mistakenly entered into the username field, so we can log it without concern.
	if len(searchResult.Entries) > 1 {
		return "", "", nil, "", fmt.Errorf(`searching for user "%s" resulted in %d search results, but expected 1 result`,
			username, len(searchResult.Entries),
		)
	}
	userEntry := searchResult.Entries[0]
	if len(userEntry.DN) == 0 {
		return "", "", nil, "", fmt.Errorf(`searching for user "%s" resulted in search result without DN`, username)
	}

	mappedUsername, err := p.getSearchResultAttributeValue(p.c.UserSearch.UsernameAttribute, userEntry, username)
	if err != nil {
		return "", "", nil, "", err
	}

	// We would like to support binary typed attributes for UIDs, so always read them as binary and encode them,
	// even when the attribute may not be binary.
	mappedUID, err := p.getSearchResultAttributeRawValueEncoded(p.c.UserSearch.UIDAttribute, userEntry, username)
	if err != nil {
		return "", "", nil, "", err
	}

	mappedGroupNames := []string{}
	if len(p.c.GroupSearch.Base) > 0 {
		mappedGroupNames, err = p.searchGroupsForUserDN(conn, userEntry.DN)
		if err != nil {
			return "", "", nil, "", err
		}
	}
	sort.Strings(mappedGroupNames)

	// Caution: Note that any other LDAP commands after this bind will be run as this user instead of as the configured BindUsername!
	err = bindFunc(conn, userEntry.DN)
	if err != nil {
		plog.DebugErr("error binding for user (if this is not the expected dn for this username, please check the user search configuration)",
			err, "upstreamName", p.GetName(), "username", username, "dn", userEntry.DN)
		ldapErr := &ldap.Error{}
		if errors.As(err, &ldapErr) && ldapErr.ResultCode == ldap.LDAPResultInvalidCredentials {
			return "", "", nil, "", nil
		}
		return "", "", nil, "", fmt.Errorf(`error binding for user "%s" using provided password against DN "%s": %w`, username, userEntry.DN, err)
	}

	return mappedUsername, mappedUID, mappedGroupNames, userEntry.DN, nil
}

func (p *Provider) defaultNamingContextRequest() *ldap.SearchRequest {
	return &ldap.SearchRequest{
		BaseDN:       "",
		Scope:        ldap.ScopeBaseObject,
		DerefAliases: ldap.NeverDerefAliases,
		SizeLimit:    2,
		TimeLimit:    90,
		TypesOnly:    false,
		Filter:       "(objectClass=*)",
		Attributes:   []string{"defaultNamingContext"},
		Controls:     nil, // don't need paging because we set the SizeLimit so small
	}
}

func (p *Provider) userSearchRequest(username string) *ldap.SearchRequest {
	// See https://ldap.com/the-ldap-search-operation for general documentation of LDAP search options.
	return &ldap.SearchRequest{
		BaseDN:       p.c.UserSearch.Base,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		SizeLimit:    2,
		TimeLimit:    90,
		TypesOnly:    false,
		Filter:       p.userSearchFilter(username),
		Attributes:   p.userSearchRequestedAttributes(),
		Controls:     nil, // this could be used to enable paging, but we're already limiting the result max size
	}
}

func (p *Provider) groupSearchRequest(userDN string) *ldap.SearchRequest {
	// See https://ldap.com/the-ldap-search-operation for general documentation of LDAP search options.
	return &ldap.SearchRequest{
		BaseDN:       p.c.GroupSearch.Base,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		SizeLimit:    0, // unlimited size because we will search with paging
		TimeLimit:    90,
		TypesOnly:    false,
		Filter:       p.groupSearchFilter(userDN),
		Attributes:   p.groupSearchRequestedAttributes(),
		Controls:     nil, // nil because ldap.SearchWithPaging() will set the appropriate controls for us
	}
}

func (p *Provider) refreshUserSearchRequest(dn string) *ldap.SearchRequest {
	// See https://ldap.com/the-ldap-search-operation for general documentation of LDAP search options.
	return &ldap.SearchRequest{
		BaseDN:       dn,
		Scope:        ldap.ScopeBaseObject,
		DerefAliases: ldap.NeverDerefAliases,
		SizeLimit:    2,
		TimeLimit:    90,
		TypesOnly:    false,
		Filter:       "(objectClass=*)", // we already have the dn, so the filter doesn't matter
		Attributes:   p.userSearchRequestedAttributes(),
		Controls:     nil, // this could be used to enable paging, but we're already limiting the result max size
	}
}

func (p *Provider) userSearchRequestedAttributes() []string {
	attributes := []string{}
	if p.c.UserSearch.UsernameAttribute != distinguishedNameAttributeName {
		attributes = append(attributes, p.c.UserSearch.UsernameAttribute)
	}
	if p.c.UserSearch.UIDAttribute != distinguishedNameAttributeName {
		attributes = append(attributes, p.c.UserSearch.UIDAttribute)
	}
	return attributes
}

func (p *Provider) groupSearchRequestedAttributes() []string {
	switch p.c.GroupSearch.GroupNameAttribute {
	case "":
		return []string{}
	case distinguishedNameAttributeName:
		return []string{}
	default:
		return []string{p.c.GroupSearch.GroupNameAttribute}
	}
}

func (p *Provider) userSearchFilter(username string) string {
	safeUsername := p.escapeUsernameForSearchFilter(username)
	if len(p.c.UserSearch.Filter) == 0 {
		return fmt.Sprintf("(%s=%s)", p.c.UserSearch.UsernameAttribute, safeUsername)
	}
	return interpolateSearchFilter(p.c.UserSearch.Filter, safeUsername)
}

func (p *Provider) groupSearchFilter(userDN string) string {
	if len(p.c.GroupSearch.Filter) == 0 {
		return fmt.Sprintf("(member=%s)", userDN)
	}
	return interpolateSearchFilter(p.c.GroupSearch.Filter, userDN)
}

func interpolateSearchFilter(filterFormat, valueToInterpolateIntoFilter string) string {
	filter := strings.ReplaceAll(filterFormat, searchFilterInterpolationLocationMarker, valueToInterpolateIntoFilter)
	if strings.HasPrefix(filter, "(") && strings.HasSuffix(filter, ")") {
		return filter
	}
	return "(" + filter + ")"
}

func (p *Provider) escapeUsernameForSearchFilter(username string) string {
	// The username is end user input, so it should be escaped before being included in a search to prevent query injection.
	return ldap.EscapeFilter(username)
}

// Returns the (potentially) binary data of the attribute's value, base64 URL encoded.
func (p *Provider) getSearchResultAttributeRawValueEncoded(attributeName string, entry *ldap.Entry, username string) (string, error) {
	if attributeName == distinguishedNameAttributeName {
		return base64.RawURLEncoding.EncodeToString([]byte(entry.DN)), nil
	}

	attributeValues := entry.GetRawAttributeValues(attributeName)

	if len(attributeValues) != 1 {
		return "", fmt.Errorf(`found %d values for attribute "%s" while searching for user "%s", but expected 1 result`,
			len(attributeValues), attributeName, username,
		)
	}

	attributeValue := attributeValues[0]
	if len(attributeValue) == 0 {
		return "", fmt.Errorf(`found empty value for attribute "%s" while searching for user "%s", but expected value to be non-empty`,
			attributeName, username,
		)
	}

	if overrideFunc := p.c.UIDAttributeParsingOverrides[attributeName]; overrideFunc != nil {
		return overrideFunc(entry)
	}

	return base64.RawURLEncoding.EncodeToString(attributeValue), nil
}

func (p *Provider) getSearchResultAttributeValue(attributeName string, entry *ldap.Entry, username string) (string, error) {
	if attributeName == distinguishedNameAttributeName {
		return entry.DN, nil
	}

	attributeValues := entry.GetAttributeValues(attributeName)

	if len(attributeValues) != 1 {
		return "", fmt.Errorf(`found %d values for attribute "%s" while searching for user "%s", but expected 1 result`,
			len(attributeValues), attributeName, username,
		)
	}

	attributeValue := attributeValues[0]
	if len(attributeValue) == 0 {
		return "", fmt.Errorf(`found empty value for attribute "%s" while searching for user "%s", but expected value to be non-empty`,
			attributeName, username,
		)
	}

	return attributeValue, nil
}

func (p *Provider) traceAuthFailure(t *trace.Trace, err error) {
	t.Step("authentication failed",
		trace.Field{Key: "authenticated", Value: false},
		trace.Field{Key: "reason", Value: err.Error()},
	)
}

func (p *Provider) traceAuthSuccess(t *trace.Trace) {
	t.Step("authentication succeeded",
		trace.Field{Key: "authenticated", Value: true},
	)
}

func (p *Provider) traceSearchBaseDiscoveryFailure(t *trace.Trace, err error) {
	t.Step("search base discovery failed",
		trace.Field{Key: "reason", Value: err.Error()})
}

func (p *Provider) traceRefreshFailure(t *trace.Trace, err error) {
	t.Step("refresh failed",
		trace.Field{Key: "reason", Value: err.Error()},
	)
}

func MicrosoftUUIDFromBinary(attributeName string) func(entry *ldap.Entry) (string, error) {
	// validation has already been done so we can just get the attribute...
	return func(entry *ldap.Entry) (string, error) {
		binaryUUID := entry.GetRawAttributeValue(attributeName)
		return microsoftUUIDFromBinary(binaryUUID)
	}
}

func microsoftUUIDFromBinary(binaryUUID []byte) (string, error) {
	uuidVal, err := uuid.FromBytes(binaryUUID) // start out with the RFC4122 version
	if err != nil {
		return "", err
	}
	// then swap it because AD stores the first 3 fields little-endian rather than the expected
	// big-endian.
	uuidVal[0], uuidVal[1], uuidVal[2], uuidVal[3] = uuidVal[3], uuidVal[2], uuidVal[1], uuidVal[0]
	uuidVal[4], uuidVal[5] = uuidVal[5], uuidVal[4]
	uuidVal[6], uuidVal[7] = uuidVal[7], uuidVal[6]
	return uuidVal.String(), nil
}

func GroupSAMAccountNameWithDomainSuffix(entry *ldap.Entry) (string, error) {
	sAMAccountNameAttributeValues := entry.GetAttributeValues(sAMAccountNameAttribute)

	if len(sAMAccountNameAttributeValues) != 1 {
		return "", fmt.Errorf(`found %d values for attribute "%s", but expected 1 result`,
			len(sAMAccountNameAttributeValues), sAMAccountNameAttribute,
		)
	}

	sAMAccountName := sAMAccountNameAttributeValues[0]
	if len(sAMAccountName) == 0 {
		return "", fmt.Errorf(`found empty value for attribute "%s", but expected value to be non-empty`,
			sAMAccountNameAttribute,
		)
	}

	distinguishedName := entry.DN
	domain, err := getDomainFromDistinguishedName(distinguishedName)
	if err != nil {
		return "", err
	}
	return sAMAccountName + "@" + domain, nil
}

var domainComponentsRegexp = regexp.MustCompile(",DC=|,dc=")

func getDomainFromDistinguishedName(distinguishedName string) (string, error) {
	domainComponents := domainComponentsRegexp.Split(distinguishedName, -1)
	if len(domainComponents) == 1 {
		return "", fmt.Errorf("did not find domain components in group dn: %s", distinguishedName)
	}
	return strings.Join(domainComponents[1:], "."), nil
}
