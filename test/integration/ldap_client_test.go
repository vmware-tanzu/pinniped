// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/authentication/user"

	"go.pinniped.dev/internal/authenticators"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/internal/upstreamldap"
	"go.pinniped.dev/test/testlib"
)

// safe to run in parallel with serial tests since it only makes read requests to our test LDAP server, see main_test.go.
func TestLDAPSearch_Parallel(t *testing.T) {
	// This test does not interact with Kubernetes itself. It is a test of our LDAP client code, and only interacts
	// with our test OpenLDAP server, which is exposed directly to this test via kubectl port-forward.
	// Theoretically we should always be able to run this test, but something about the kubectl port forwarding
	// was very flaky on AKS, so we'll get the coverage by only running it on kind.
	env := testlib.IntegrationEnv(t).WithKubeDistribution(testlib.KindDistro)

	// Note that these tests depend on the values hard-coded in the LDIF file in test/deploy/tools/ldap.yaml.
	// It requires the test LDAP server from the tools deployment.
	if len(env.ToolsNamespace) == 0 || !strings.Contains(env.SupervisorUpstreamLDAP.Host, "tools.svc.cluster.local") {
		t.Skip("Skipping test because it requires the test OpenLDAP server in the tools namespace of the target cluster.")
	}

	ctx, cancelFunc := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancelFunc() // this will send SIGKILL to the subprocess, just in case
	})

	localhostPorts := findRecentlyUnusedLocalhostPorts(t, 3)
	ldapLocalhostPort := localhostPorts[0]
	ldapsLocalhostPort := localhostPorts[1]
	unusedLocalhostPort := localhostPorts[2]

	// Expose the test LDAP server's TLS port on the localhost.
	startKubectlPortForward(ctx, t, ldapsLocalhostPort, "ldaps", "ldap", env.ToolsNamespace)

	// Expose the test LDAP server's StartTLS port on the localhost.
	startKubectlPortForward(ctx, t, ldapLocalhostPort, "ldap", "ldap", env.ToolsNamespace)

	providerConfig := func(editFunc func(p *upstreamldap.ProviderConfig)) *upstreamldap.ProviderConfig {
		providerConfig := defaultProviderConfig(env, ldapsLocalhostPort)
		if editFunc != nil {
			editFunc(providerConfig)
		}
		return providerConfig
	}

	pinnyPassword := env.SupervisorUpstreamLDAP.TestUserPassword

	b64 := func(s string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(s))
	}

	tests := []struct {
		name                string
		username            string
		password            string
		provider            *upstreamldap.Provider
		wantError           testutil.RequireErrorStringFunc
		wantAuthResponse    *authenticators.Response
		wantUnauthenticated bool
	}{
		{
			name:     "happy path with TLS",
			username: "pinny",
			password: pinnyPassword,
			provider: upstreamldap.New(*providerConfig(nil)),
			wantAuthResponse: &authenticators.Response{
				User:                   &user.DefaultInfo{Name: "pinny", UID: b64("1000"), Groups: []string{"ball-game-players", "seals"}},
				DN:                     "cn=pinny,ou=users,dc=pinniped,dc=dev",
				ExtraRefreshAttributes: map[string]string{},
			},
		},
		{
			name:     "happy path with StartTLS",
			username: "pinny",
			password: pinnyPassword,
			provider: upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) {
				p.Host = "127.0.0.1:" + ldapLocalhostPort
				p.ConnectionProtocol = upstreamldap.StartTLS
			})),
			wantAuthResponse: &authenticators.Response{
				User:                   &user.DefaultInfo{Name: "pinny", UID: b64("1000"), Groups: []string{"ball-game-players", "seals"}},
				DN:                     "cn=pinny,ou=users,dc=pinniped,dc=dev",
				ExtraRefreshAttributes: map[string]string{},
			},
		},
		{
			name:     "using a different user search base",
			username: "pinny",
			password: pinnyPassword,
			provider: upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) { p.UserSearch.Base = "dc=pinniped,dc=dev" })),
			wantAuthResponse: &authenticators.Response{
				User:                   &user.DefaultInfo{Name: "pinny", UID: b64("1000"), Groups: []string{"ball-game-players", "seals"}},
				DN:                     "cn=pinny,ou=users,dc=pinniped,dc=dev",
				ExtraRefreshAttributes: map[string]string{},
			},
		},
		{
			name:     "when the user search filter is already wrapped by parenthesis",
			username: "pinny",
			password: pinnyPassword,
			provider: upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) { p.UserSearch.Filter = "(cn={})" })),
			wantAuthResponse: &authenticators.Response{
				User:                   &user.DefaultInfo{Name: "pinny", UID: b64("1000"), Groups: []string{"ball-game-players", "seals"}},
				DN:                     "cn=pinny,ou=users,dc=pinniped,dc=dev",
				ExtraRefreshAttributes: map[string]string{},
			},
		},
		{
			name:     "when the UsernameAttribute is dn and a user search filter is provided",
			username: "pinny",
			password: pinnyPassword,
			provider: upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) {
				p.UserSearch.UsernameAttribute = "dn"
				p.UserSearch.Filter = "cn={}"
			})),
			wantAuthResponse: &authenticators.Response{
				User:                   &user.DefaultInfo{Name: "cn=pinny,ou=users,dc=pinniped,dc=dev", UID: b64("1000"), Groups: []string{"ball-game-players", "seals"}},
				DN:                     "cn=pinny,ou=users,dc=pinniped,dc=dev",
				ExtraRefreshAttributes: map[string]string{},
			},
		},
		{
			name:     "when the user search filter allows for different ways of logging in and the first one is used",
			username: "pinny",
			password: pinnyPassword,
			provider: upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) {
				p.UserSearch.Filter = "(|(cn={})(mail={}))"
			})),
			wantAuthResponse: &authenticators.Response{
				User:                   &user.DefaultInfo{Name: "pinny", UID: b64("1000"), Groups: []string{"ball-game-players", "seals"}},
				DN:                     "cn=pinny,ou=users,dc=pinniped,dc=dev",
				ExtraRefreshAttributes: map[string]string{},
			},
		},
		{
			name:     "when the user search filter allows for different ways of logging in and the second one is used",
			username: "pinny.ldap@example.com",
			password: pinnyPassword,
			provider: upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) {
				p.UserSearch.Filter = "(|(cn={})(mail={}))"
			})),
			wantAuthResponse: &authenticators.Response{
				User:                   &user.DefaultInfo{Name: "pinny", UID: b64("1000"), Groups: []string{"ball-game-players", "seals"}},
				DN:                     "cn=pinny,ou=users,dc=pinniped,dc=dev",
				ExtraRefreshAttributes: map[string]string{},
			},
		},
		{
			name:     "when the UIDAttribute is dn",
			username: "pinny",
			password: pinnyPassword,
			provider: upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) { p.UserSearch.UIDAttribute = "dn" })),
			wantAuthResponse: &authenticators.Response{
				User:                   &user.DefaultInfo{Name: "pinny", UID: b64("cn=pinny,ou=users,dc=pinniped,dc=dev"), Groups: []string{"ball-game-players", "seals"}},
				DN:                     "cn=pinny,ou=users,dc=pinniped,dc=dev",
				ExtraRefreshAttributes: map[string]string{},
			},
		},
		{
			name:     "when the UIDAttribute is sn",
			username: "pinny",
			password: pinnyPassword,
			provider: upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) { p.UserSearch.UIDAttribute = "sn" })),
			wantAuthResponse: &authenticators.Response{
				User:                   &user.DefaultInfo{Name: "pinny", UID: b64("Seal"), Groups: []string{"ball-game-players", "seals"}},
				DN:                     "cn=pinny,ou=users,dc=pinniped,dc=dev",
				ExtraRefreshAttributes: map[string]string{},
			},
		},
		{
			name:     "when the UsernameAttribute is sn",
			username: "seAl", // note that this is not case-sensitive! sn=Seal. The server decides which fields are compared case-sensitive.
			password: pinnyPassword,
			provider: upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) { p.UserSearch.UsernameAttribute = "sn" })),
			wantAuthResponse: &authenticators.Response{
				User:                   &user.DefaultInfo{Name: "Seal", UID: b64("1000"), Groups: []string{"ball-game-players", "seals"}},
				DN:                     "cn=pinny,ou=users,dc=pinniped,dc=dev", // note that the final answer has case preserved from the entry
				ExtraRefreshAttributes: map[string]string{},
			},
		},
		{
			name:     "when the UsernameAttribute or UIDAttribute are attributes whose value contains UTF-8 data",
			username: "pinny",
			password: pinnyPassword,
			provider: upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) {
				p.UserSearch.Filter = "cn={}"
				p.UserSearch.UsernameAttribute = "givenName"
				p.UserSearch.UIDAttribute = "givenName"
			})),
			wantAuthResponse: &authenticators.Response{
				User:                   &user.DefaultInfo{Name: "Pinny the 🦭", UID: b64("Pinny the 🦭"), Groups: []string{"ball-game-players", "seals"}},
				DN:                     "cn=pinny,ou=users,dc=pinniped,dc=dev",
				ExtraRefreshAttributes: map[string]string{},
			},
		},
		{
			name:     "when the search filter is searching on an attribute whose value contains UTF-8 data",
			username: "Pinny the 🦭",
			password: pinnyPassword,
			provider: upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) {
				p.UserSearch.Filter = "givenName={}"
				p.UserSearch.UsernameAttribute = "cn"
			})),
			wantAuthResponse: &authenticators.Response{
				User:                   &user.DefaultInfo{Name: "pinny", UID: b64("1000"), Groups: []string{"ball-game-players", "seals"}},
				DN:                     "cn=pinny,ou=users,dc=pinniped,dc=dev",
				ExtraRefreshAttributes: map[string]string{},
			},
		},
		{
			name:     "when the UsernameAttribute is dn and there is no user search filter provided",
			username: "cn=pinny,ou=users,dc=pinniped,dc=dev",
			password: pinnyPassword,
			provider: upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) {
				p.UserSearch.UsernameAttribute = "dn"
				p.UserSearch.Filter = ""
			})),
			wantError: testutil.WantExactErrorString(`must specify UserSearch Filter when UserSearch UsernameAttribute is "dn"`),
		},
		{
			name:     "group search disabled",
			username: "pinny",
			password: pinnyPassword,
			provider: upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) {
				p.GroupSearch.Base = ""
			})),
			wantAuthResponse: &authenticators.Response{
				User:                   &user.DefaultInfo{Name: "pinny", UID: b64("1000"), Groups: []string{}},
				DN:                     "cn=pinny,ou=users,dc=pinniped,dc=dev",
				ExtraRefreshAttributes: map[string]string{},
			},
		},
		{
			name:     "group search base causes no groups to be found for user",
			username: "pinny",
			password: pinnyPassword,
			provider: upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) {
				p.GroupSearch.Base = "ou=users,dc=pinniped,dc=dev" // there are no groups under this part of the tree
			})),
			wantAuthResponse: &authenticators.Response{
				User:                   &user.DefaultInfo{Name: "pinny", UID: b64("1000"), Groups: []string{}},
				DN:                     "cn=pinny,ou=users,dc=pinniped,dc=dev",
				ExtraRefreshAttributes: map[string]string{},
			},
		},
		{
			name:     "using dn as the group name attribute",
			username: "pinny",
			password: pinnyPassword,
			provider: upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) {
				p.GroupSearch.GroupNameAttribute = "dn"
			})),
			wantAuthResponse: &authenticators.Response{
				User: &user.DefaultInfo{Name: "pinny", UID: b64("1000"), Groups: []string{
					"cn=ball-game-players,ou=beach-groups,ou=groups,dc=pinniped,dc=dev",
					"cn=seals,ou=groups,dc=pinniped,dc=dev",
				}},
				DN:                     "cn=pinny,ou=users,dc=pinniped,dc=dev",
				ExtraRefreshAttributes: map[string]string{},
			},
		},
		{
			name:     "using the default group name attribute, which is dn",
			username: "pinny",
			password: pinnyPassword,
			provider: upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) {
				p.GroupSearch.GroupNameAttribute = ""
			})),
			wantAuthResponse: &authenticators.Response{
				User: &user.DefaultInfo{Name: "pinny", UID: b64("1000"), Groups: []string{
					"cn=ball-game-players,ou=beach-groups,ou=groups,dc=pinniped,dc=dev",
					"cn=seals,ou=groups,dc=pinniped,dc=dev",
				}},
				DN:                     "cn=pinny,ou=users,dc=pinniped,dc=dev",
				ExtraRefreshAttributes: map[string]string{},
			},
		},
		{
			name:     "using some other custom group name attribute",
			username: "pinny",
			password: pinnyPassword,
			provider: upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) {
				p.GroupSearch.GroupNameAttribute = "objectClass" // silly example, but still a meaningful test
			})),
			wantAuthResponse: &authenticators.Response{
				User:                   &user.DefaultInfo{Name: "pinny", UID: b64("1000"), Groups: []string{"groupOfNames"}},
				DN:                     "cn=pinny,ou=users,dc=pinniped,dc=dev",
				ExtraRefreshAttributes: map[string]string{},
			},
		},
		{
			name:     "using a more complex group search filter",
			username: "pinny",
			password: pinnyPassword,
			provider: upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) {
				p.GroupSearch.Filter = "(&(&(objectClass=groupOfNames)(member={}))(cn=seals))"
			})),
			wantAuthResponse: &authenticators.Response{
				User:                   &user.DefaultInfo{Name: "pinny", UID: b64("1000"), Groups: []string{"seals"}},
				DN:                     "cn=pinny,ou=users,dc=pinniped,dc=dev",
				ExtraRefreshAttributes: map[string]string{},
			},
		},
		{
			name:     "using a group filter which causes no groups to be found for the user",
			username: "pinny",
			password: pinnyPassword,
			provider: upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) {
				p.GroupSearch.Filter = "foobar={}" // foobar is not a valid attribute name for this LDAP server's schema
			})),
			wantAuthResponse: &authenticators.Response{
				User:                   &user.DefaultInfo{Name: "pinny", UID: b64("1000"), Groups: []string{}},
				DN:                     "cn=pinny,ou=users,dc=pinniped,dc=dev",
				ExtraRefreshAttributes: map[string]string{},
			},
		},
		{
			name:     "using a group search with UserAttributeForFilter set to uid",
			username: "pinny",
			password: pinnyPassword,
			provider: upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) {
				p.GroupSearch.Filter = "&(objectClass=posixGroup)(memberUid={})"
				p.GroupSearch.UserAttributeForFilter = "uid"
			})),
			wantAuthResponse: &authenticators.Response{
				User:                   &user.DefaultInfo{Name: "pinny", UID: b64("1000"), Groups: []string{"ball-game-players-posix", "seals-posix"}},
				DN:                     "cn=pinny,ou=users,dc=pinniped,dc=dev",
				ExtraRefreshAttributes: map[string]string{},
			},
		},
		{
			name:     "using a group search with UserAttributeForFilter set to cn",
			username: "pinny",
			password: pinnyPassword,
			provider: upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) {
				p.GroupSearch.Filter = "&(objectClass=posixGroup)(memberUid={})"
				p.GroupSearch.UserAttributeForFilter = "cn" // this only works because pinny's uid and cn are both "pinny"
			})),
			wantAuthResponse: &authenticators.Response{
				User:                   &user.DefaultInfo{Name: "pinny", UID: b64("1000"), Groups: []string{"ball-game-players-posix", "seals-posix"}},
				DN:                     "cn=pinny,ou=users,dc=pinniped,dc=dev",
				ExtraRefreshAttributes: map[string]string{},
			},
		},
		{
			name:     "using a group search with UserAttributeForFilter and a creative filter",
			username: "pinny",
			password: pinnyPassword,
			provider: upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) {
				p.GroupSearch.Filter = "&(objectClass=groupOfNames)(member=cn={},ou=users,dc=pinniped,dc=dev)" // not the typical usage, but possible
				p.GroupSearch.UserAttributeForFilter = "cn"
			})),
			wantAuthResponse: &authenticators.Response{
				User:                   &user.DefaultInfo{Name: "pinny", UID: b64("1000"), Groups: []string{"ball-game-players", "seals"}},
				DN:                     "cn=pinny,ou=users,dc=pinniped,dc=dev",
				ExtraRefreshAttributes: map[string]string{},
			},
		},
		{
			name:     "using a group search with UserAttributeForFilter set to givenName",
			username: "pinny",
			password: pinnyPassword,
			provider: upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) {
				p.GroupSearch.Filter = "&(objectClass=posixGroup)(memberUid={})"
				p.GroupSearch.UserAttributeForFilter = "givenName" // pinny's givenName is not "pinny" so it should not find any groups, and also should not error on the emoji in the givenName
			})),
			wantAuthResponse: &authenticators.Response{
				User:                   &user.DefaultInfo{Name: "pinny", UID: b64("1000"), Groups: []string{}},
				DN:                     "cn=pinny,ou=users,dc=pinniped,dc=dev",
				ExtraRefreshAttributes: map[string]string{},
			},
		},
		{
			name:     "using a group search with UserAttributeForFilter set to gidNumber",
			username: "pinny",
			password: pinnyPassword,
			provider: upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) {
				p.GroupSearch.Filter = "&(objectClass=posixGroup)(gidNumber={})"
				p.GroupSearch.UserAttributeForFilter = "gidNumber"
			})),
			wantAuthResponse: &authenticators.Response{
				User:                   &user.DefaultInfo{Name: "pinny", UID: b64("1000"), Groups: []string{"walruses-posix"}},
				DN:                     "cn=pinny,ou=users,dc=pinniped,dc=dev",
				ExtraRefreshAttributes: map[string]string{},
			},
		},
		{
			name:     "using a group search with UserAttributeForFilter set to dn",
			username: "pinny",
			password: pinnyPassword,
			provider: upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) {
				p.GroupSearch.UserAttributeForFilter = "dn" // this should act the same as when it is not set
			})),
			wantAuthResponse: &authenticators.Response{
				User:                   &user.DefaultInfo{Name: "pinny", UID: b64("1000"), Groups: []string{"ball-game-players", "seals"}},
				DN:                     "cn=pinny,ou=users,dc=pinniped,dc=dev",
				ExtraRefreshAttributes: map[string]string{},
			},
		},
		{
			name:     "using a group search with UserAttributeForFilter set to an attribute that does not exist on the user",
			username: "pinny",
			password: pinnyPassword,
			provider: upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) {
				p.GroupSearch.UserAttributeForFilter = "foobar"
			})),
			wantError: testutil.WantExactErrorString(`found 0 values for attribute "foobar" while searching for user "pinny", but expected 1 result`),
		},
		{
			name:      "when the bind user username is not a valid DN",
			username:  "pinny",
			password:  pinnyPassword,
			provider:  upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) { p.BindUsername = "invalid-dn" })),
			wantError: testutil.WantExactErrorString(`error binding as "invalid-dn" before user search: LDAP Result Code 34 "Invalid DN Syntax": invalid DN`),
		},
		{
			name:      "when the bind user username is wrong",
			username:  "pinny",
			password:  pinnyPassword,
			provider:  upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) { p.BindUsername = "cn=wrong,dc=pinniped,dc=dev" })),
			wantError: testutil.WantExactErrorString(`error binding as "cn=wrong,dc=pinniped,dc=dev" before user search: LDAP Result Code 49 "Invalid Credentials": `),
		},
		{
			name:      "when the bind user password is wrong",
			username:  "pinny",
			password:  pinnyPassword,
			provider:  upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) { p.BindPassword = "wrong-password" })),
			wantError: testutil.WantExactErrorString(`error binding as "cn=admin,dc=pinniped,dc=dev" before user search: LDAP Result Code 49 "Invalid Credentials": `),
		},
		{
			name:     "when the bind user username is wrong with StartTLS: example of an error after successful connection with StartTLS",
			username: "pinny",
			password: pinnyPassword,
			provider: upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) {
				p.Host = "127.0.0.1:" + ldapLocalhostPort
				p.ConnectionProtocol = upstreamldap.StartTLS
				p.BindUsername = "cn=wrong,dc=pinniped,dc=dev"
			})),
			wantError: testutil.WantExactErrorString(`error binding as "cn=wrong,dc=pinniped,dc=dev" before user search: LDAP Result Code 49 "Invalid Credentials": `),
		},
		{
			name:                "when the end user password is wrong",
			username:            "pinny",
			password:            "wrong-pinny-password",
			provider:            upstreamldap.New(*providerConfig(nil)),
			wantUnauthenticated: true,
		},
		{
			name:                "when the end user password has the wrong case (passwords are compared as case-sensitive)",
			username:            "pinny",
			password:            strings.ToUpper(pinnyPassword),
			provider:            upstreamldap.New(*providerConfig(nil)),
			wantUnauthenticated: true,
		},
		{
			name:                "when the end user username is wrong",
			username:            "wrong-username",
			password:            pinnyPassword,
			provider:            upstreamldap.New(*providerConfig(nil)),
			wantUnauthenticated: true,
		},
		{
			name:      "when the user search filter does not compile",
			username:  "pinny",
			password:  pinnyPassword,
			provider:  upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) { p.UserSearch.Filter = "*" })),
			wantError: testutil.WantExactErrorString(`error searching for user: LDAP Result Code 201 "Filter Compile Error": ldap: error parsing filter`),
		},
		{
			name:      "when the group search filter does not compile",
			username:  "pinny",
			password:  pinnyPassword,
			provider:  upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) { p.GroupSearch.Filter = "*" })),
			wantError: testutil.WantExactErrorString(`error searching for group memberships for user with DN "cn=pinny,ou=users,dc=pinniped,dc=dev": LDAP Result Code 201 "Filter Compile Error": ldap: error parsing filter`),
		},
		{
			name:     "when there are too many search results for the user",
			username: "pinny",
			password: pinnyPassword,
			provider: upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) {
				p.UserSearch.Filter = "objectClass=*" // overly broad search filter
			})),
			wantError: testutil.WantExactErrorString(`error searching for user: LDAP Result Code 4 "Size Limit Exceeded": `),
		},
		{
			name:      "when the server is unreachable with TLS",
			username:  "pinny",
			password:  pinnyPassword,
			provider:  upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) { p.Host = "127.0.0.1:" + unusedLocalhostPort })),
			wantError: testutil.WantSprintfErrorString(`error dialing host "127.0.0.1:%s": LDAP Result Code 200 "Network Error": dial tcp 127.0.0.1:%s: connect: connection refused`, unusedLocalhostPort, unusedLocalhostPort),
		},
		{
			name:     "when the server is unreachable with StartTLS",
			username: "pinny",
			password: pinnyPassword,
			provider: upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) {
				p.Host = "127.0.0.1:" + unusedLocalhostPort
				p.ConnectionProtocol = upstreamldap.StartTLS
			})),
			wantError: testutil.WantSprintfErrorString(`error dialing host "127.0.0.1:%s": LDAP Result Code 200 "Network Error": dial tcp 127.0.0.1:%s: connect: connection refused`, unusedLocalhostPort, unusedLocalhostPort),
		},
		{
			name:      "when the server is not parsable with TLS",
			username:  "pinny",
			password:  pinnyPassword,
			provider:  upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) { p.Host = "too:many:ports" })),
			wantError: testutil.WantExactErrorString(`error dialing host "too:many:ports": LDAP Result Code 200 "Network Error": host "too:many:ports" is not a valid hostname or IP address`),
		},
		{
			name:     "when the server is not parsable with StartTLS",
			username: "pinny",
			password: pinnyPassword,
			provider: upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) {
				p.Host = "127.0.0.1:" + ldapLocalhostPort
				p.ConnectionProtocol = upstreamldap.StartTLS
				p.Host = "too:many:ports"
			})),
			wantError: testutil.WantExactErrorString(`error dialing host "too:many:ports": LDAP Result Code 200 "Network Error": host "too:many:ports" is not a valid hostname or IP address`),
		},
		{
			name:      "when the CA bundle is not parsable with TLS",
			username:  "pinny",
			password:  pinnyPassword,
			provider:  upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) { p.CABundle = []byte("invalid-pem") })),
			wantError: testutil.WantSprintfErrorString(`error dialing host "127.0.0.1:%s": LDAP Result Code 200 "Network Error": could not parse CA bundle`, ldapsLocalhostPort),
		},
		{
			name:     "when the CA bundle is not parsable with StartTLS",
			username: "pinny",
			password: pinnyPassword,
			provider: upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) {
				p.Host = "127.0.0.1:" + ldapLocalhostPort
				p.ConnectionProtocol = upstreamldap.StartTLS
				p.CABundle = []byte("invalid-pem")
			})),
			wantError: testutil.WantSprintfErrorString(`error dialing host "127.0.0.1:%s": LDAP Result Code 200 "Network Error": could not parse CA bundle`, ldapLocalhostPort),
		},
		{
			name:      "when the CA bundle does not cause the host to be trusted with TLS",
			username:  "pinny",
			password:  pinnyPassword,
			provider:  upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) { p.CABundle = nil })),
			wantError: testutil.WantSprintfErrorString(`error dialing host "127.0.0.1:%s": LDAP Result Code 200 "Network Error": tls: failed to verify certificate: x509: certificate signed by unknown authority`, ldapsLocalhostPort),
		},
		{
			name:     "when the CA bundle does not cause the host to be trusted with StartTLS",
			username: "pinny",
			password: pinnyPassword,
			provider: upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) {
				p.Host = "127.0.0.1:" + ldapLocalhostPort
				p.ConnectionProtocol = upstreamldap.StartTLS
				p.CABundle = nil
			})),
			wantError: testutil.WantSprintfErrorString(`error dialing host "127.0.0.1:%s": LDAP Result Code 200 "Network Error": TLS handshake failed (tls: failed to verify certificate: x509: certificate signed by unknown authority)`, ldapLocalhostPort),
		},
		{
			name:      "when trying to use TLS to connect to a port which only supports StartTLS",
			username:  "pinny",
			password:  pinnyPassword,
			provider:  upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) { p.Host = "127.0.0.1:" + ldapLocalhostPort })),
			wantError: testutil.WantSprintfErrorString(`error dialing host "127.0.0.1:%s": LDAP Result Code 200 "Network Error": EOF`, ldapLocalhostPort),
		},
		{
			name:      "when trying to use StartTLS to connect to a port which only supports TLS",
			username:  "pinny",
			password:  pinnyPassword,
			provider:  upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) { p.ConnectionProtocol = upstreamldap.StartTLS })),
			wantError: testutil.WantSprintfErrorString(`error dialing host "127.0.0.1:%s": unable to read LDAP response packet: EOF`, ldapsLocalhostPort),
		},
		{
			name:      "when the UsernameAttribute attribute has multiple values in the entry",
			username:  "wally.ldap@example.com",
			password:  "unused-because-error-is-before-bind",
			provider:  upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) { p.UserSearch.UsernameAttribute = "mail" })),
			wantError: testutil.WantExactErrorString(`found 2 values for attribute "mail" while searching for user "wally.ldap@example.com", but expected 1 result`),
		},
		{
			name:      "when the UIDAttribute attribute has multiple values in the entry",
			username:  "wally",
			password:  "unused-because-error-is-before-bind",
			provider:  upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) { p.UserSearch.UIDAttribute = "mail" })),
			wantError: testutil.WantExactErrorString(`found 2 values for attribute "mail" while searching for user "wally", but expected 1 result`),
		},
		{
			name:     "when the UsernameAttribute attribute is not found in the entry",
			username: "wally",
			password: "unused-because-error-is-before-bind",
			provider: upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) {
				p.UserSearch.Filter = "cn={}"
				p.UserSearch.UsernameAttribute = "attr-does-not-exist"
			})),
			wantError: testutil.WantExactErrorString(`found 0 values for attribute "attr-does-not-exist" while searching for user "wally", but expected 1 result`),
		},
		{
			name:      "when the UIDAttribute attribute is not found in the entry",
			username:  "wally",
			password:  "unused-because-error-is-before-bind",
			provider:  upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) { p.UserSearch.UIDAttribute = "attr-does-not-exist" })),
			wantError: testutil.WantExactErrorString(`found 0 values for attribute "attr-does-not-exist" while searching for user "wally", but expected 1 result`),
		},
		{
			name:      "when the UsernameAttribute has the wrong case",
			username:  "Seal",
			password:  pinnyPassword,
			provider:  upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) { p.UserSearch.UsernameAttribute = "SN" })), // this is case-sensitive
			wantError: testutil.WantExactErrorString(`found 0 values for attribute "SN" while searching for user "Seal", but expected 1 result`),
		},
		{
			name:      "when the UIDAttribute has the wrong case",
			username:  "pinny",
			password:  pinnyPassword,
			provider:  upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) { p.UserSearch.UIDAttribute = "SN" })), // this is case-sensitive
			wantError: testutil.WantExactErrorString(`found 0 values for attribute "SN" while searching for user "pinny", but expected 1 result`),
		},
		{
			name:      "when the GroupNameAttribute has the wrong case",
			username:  "pinny",
			password:  pinnyPassword,
			provider:  upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) { p.GroupSearch.GroupNameAttribute = "CN" })), // this is case-sensitive
			wantError: testutil.WantExactErrorString(`error searching for group memberships for user with DN "cn=pinny,ou=users,dc=pinniped,dc=dev": found 0 values for attribute "CN" while searching for user "cn=pinny,ou=users,dc=pinniped,dc=dev", but expected 1 result`),
		},
		{
			name:     "when the UsernameAttribute is DN and has the wrong case",
			username: "pinny",
			password: pinnyPassword,
			provider: upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) {
				p.UserSearch.UsernameAttribute = "DN" // dn must be lower-case
				p.UserSearch.Filter = "cn={}"
			})),
			wantError: testutil.WantExactErrorString(`found 0 values for attribute "DN" while searching for user "pinny", but expected 1 result`),
		},
		{
			name:     "when the UIDAttribute is DN and has the wrong case",
			username: "pinny",
			password: pinnyPassword,
			provider: upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) {
				p.UserSearch.UIDAttribute = "DN" // dn must be lower-case
			})),
			wantError: testutil.WantExactErrorString(`found 0 values for attribute "DN" while searching for user "pinny", but expected 1 result`),
		},
		{
			name:     "when the GroupNameAttribute is DN and has the wrong case",
			username: "pinny",
			password: pinnyPassword,
			provider: upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) {
				p.GroupSearch.GroupNameAttribute = "DN" // dn must be lower-case
			})),
			wantError: testutil.WantExactErrorString(`error searching for group memberships for user with DN "cn=pinny,ou=users,dc=pinniped,dc=dev": found 0 values for attribute "DN" while searching for user "cn=pinny,ou=users,dc=pinniped,dc=dev", but expected 1 result`),
		},
		{
			name:      "when the user search base is invalid",
			username:  "pinny",
			password:  pinnyPassword,
			provider:  upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) { p.UserSearch.Base = "invalid-base" })),
			wantError: testutil.WantExactErrorString(`error searching for user: LDAP Result Code 34 "Invalid DN Syntax": invalid DN`),
		},
		{
			name:      "when the group search base is invalid",
			username:  "pinny",
			password:  pinnyPassword,
			provider:  upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) { p.GroupSearch.Base = "invalid-base" })),
			wantError: testutil.WantExactErrorString(`error searching for group memberships for user with DN "cn=pinny,ou=users,dc=pinniped,dc=dev": LDAP Result Code 34 "Invalid DN Syntax": invalid DN`),
		},
		{
			name:      "when the user search base does not exist",
			username:  "pinny",
			password:  pinnyPassword,
			provider:  upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) { p.UserSearch.Base = "ou=does-not-exist,dc=pinniped,dc=dev" })),
			wantError: testutil.WantExactErrorString(`error searching for user: LDAP Result Code 32 "No Such Object": `),
		},
		{
			name:      "when the group search base does not exist",
			username:  "pinny",
			password:  pinnyPassword,
			provider:  upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) { p.GroupSearch.Base = "ou=does-not-exist,dc=pinniped,dc=dev" })),
			wantError: testutil.WantExactErrorString(`error searching for group memberships for user with DN "cn=pinny,ou=users,dc=pinniped,dc=dev": LDAP Result Code 32 "No Such Object": `),
		},
		{
			name:                "when the user search base causes no search results",
			username:            "pinny",
			password:            pinnyPassword,
			provider:            upstreamldap.New(*providerConfig(func(p *upstreamldap.ProviderConfig) { p.UserSearch.Base = "ou=groups,dc=pinniped,dc=dev" })),
			wantUnauthenticated: true,
		},
		{
			name:                "when there is no username specified",
			username:            "",
			password:            pinnyPassword,
			provider:            upstreamldap.New(*providerConfig(nil)),
			wantUnauthenticated: true,
		},
		{
			name:      "when there is no password specified",
			username:  "pinny",
			password:  "",
			provider:  upstreamldap.New(*providerConfig(nil)),
			wantError: testutil.WantExactErrorString(`error binding for user "pinny" using provided password against DN "cn=pinny,ou=users,dc=pinniped,dc=dev": LDAP Result Code 206 "Empty password not allowed by the client": ldap: empty password not allowed by the client`),
		},
		{
			name:                "when the user has no password in their entry",
			username:            "olive",
			password:            "anything",
			provider:            upstreamldap.New(*providerConfig(nil)),
			wantUnauthenticated: true,
		},
	}

	for _, test := range tests {
		tt := test
		t.Run(tt.name, func(t *testing.T) {
			authResponse, authenticated, err := tt.provider.AuthenticateUser(ctx, tt.username, tt.password)

			switch {
			case tt.wantError != nil:
				testutil.RequireErrorStringFromErr(t, err, tt.wantError)
				require.False(t, authenticated, "expected the user not to be authenticated, but they were")
				require.Nil(t, authResponse)
			case tt.wantUnauthenticated:
				require.NoError(t, err)
				require.False(t, authenticated, "expected the user not to be authenticated, but they were")
				require.Nil(t, authResponse)
			default:
				require.NoError(t, err)
				require.True(t, authenticated, "expected the user to be authenticated, but they were not")
				require.Equal(t, tt.wantAuthResponse, authResponse)
			}
		})
	}
}

func TestSimultaneousLDAPRequestsOnSingleProvider(t *testing.T) {
	// This test does not interact with Kubernetes itself. It is a test of our LDAP client code, and only interacts
	// with our test OpenLDAP server, which is exposed directly to this test via kubectl port-forward.
	// Theoretically we should always be able to run this test, but something about the kubectl port forwarding
	// was very flaky on AKS, so we'll get the coverage by only running it on kind.
	env := testlib.IntegrationEnv(t).WithKubeDistribution(testlib.KindDistro)

	// Note that these tests depend on the values hard-coded in the LDIF file in test/deploy/tools/ldap.yaml.
	// It requires the test LDAP server from the tools deployment.
	if len(env.ToolsNamespace) == 0 || !strings.Contains(env.SupervisorUpstreamLDAP.Host, "tools.svc.cluster.local") {
		t.Skip("Skipping test because it requires the test OpenLDAP server in the tools namespace of the target cluster.")
	}

	ctx, cancelFunc := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancelFunc() // this will send SIGKILL to the subprocess, just in case
	})

	ldapHostPort := findRecentlyUnusedLocalhostPorts(t, 1)[0]

	// Expose the the test LDAP server's TLS port on the localhost.
	startKubectlPortForward(ctx, t, ldapHostPort, "ldaps", "ldap", env.ToolsNamespace)

	provider := upstreamldap.New(*defaultProviderConfig(env, ldapHostPort))

	b64 := func(s string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(s))
	}

	// Making multiple simultaneous requests on the same upstreamldap.Provider instance should all succeed
	// without triggering the race detector.
	iterations := 150
	resultCh := make(chan authUserResult, iterations)
	for range iterations {
		go func() {
			authUserCtx, authUserCtxCancelFunc := context.WithTimeout(context.Background(), 2*time.Minute)
			defer authUserCtxCancelFunc()

			authResponse, authenticated, err := provider.AuthenticateUser(authUserCtx, env.SupervisorUpstreamLDAP.TestUserCN, env.SupervisorUpstreamLDAP.TestUserPassword)
			resultCh <- authUserResult{
				response:      authResponse,
				authenticated: authenticated,
				err:           err,
			}
		}()
	}
	for range iterations {
		result := <-resultCh
		// Record failures but allow the test to keep running so that all the background goroutines have a chance to try.
		assert.NoError(t, result.err)
		assert.True(t, result.authenticated, "expected the user to be authenticated, but they were not")
		assert.Equal(t, &authenticators.Response{
			User:                   &user.DefaultInfo{Name: "pinny", UID: b64("1000"), Groups: []string{"ball-game-players", "seals"}},
			DN:                     "cn=pinny,ou=users,dc=pinniped,dc=dev",
			ExtraRefreshAttributes: map[string]string{},
		}, result.response)
	}
}

type authUserResult struct {
	response      *authenticators.Response
	authenticated bool
	err           error
}

func defaultProviderConfig(env *testlib.TestEnv, port string) *upstreamldap.ProviderConfig {
	return &upstreamldap.ProviderConfig{
		Name:               "test-ldap-provider",
		Host:               "127.0.0.1:" + port,
		ConnectionProtocol: upstreamldap.TLS,
		CABundle:           []byte(env.SupervisorUpstreamLDAP.CABundle),
		BindUsername:       "cn=admin,dc=pinniped,dc=dev",
		BindPassword:       "password",
		UserSearch: upstreamldap.UserSearchConfig{
			Base:              "ou=users,dc=pinniped,dc=dev",
			Filter:            "", // defaults to UsernameAttribute={}, i.e. "cn={}" in this case
			UsernameAttribute: "cn",
			UIDAttribute:      "uidNumber",
		},
		GroupSearch: upstreamldap.GroupSearchConfig{
			Base:               "ou=groups,dc=pinniped,dc=dev",
			Filter:             "",   // defaults to member={}
			GroupNameAttribute: "cn", // defaults to dn, but here we set it to cn
		},
	}
}

func startKubectlPortForward(ctx context.Context, t *testing.T, hostPort, remotePort, serviceName, namespace string) {
	t.Helper()
	startLongRunningCommandAndWaitForInitialOutput(ctx, t,
		"kubectl",
		[]string{
			"port-forward",
			fmt.Sprintf("service/%s", serviceName),
			fmt.Sprintf("%s:%s", hostPort, remotePort),
			"-n", namespace,
		},
		"Forwarding from ",
		"stdout",
	)
}

func findRecentlyUnusedLocalhostPorts(t *testing.T, howManyPorts int) []string {
	t.Helper()

	listeners := make([]net.Listener, howManyPorts)
	for i := range howManyPorts {
		var err error
		listeners[i], err = net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
	}

	ports := make([]string, len(listeners))
	for i, listener := range listeners {
		splitHostAndPort := strings.Split(listener.Addr().String(), ":")
		require.Len(t, splitHostAndPort, 2)
		ports[i] = splitHostAndPort[1]
	}

	for _, listener := range listeners {
		require.NoError(t, listener.Close())
	}

	return ports
}

func startLongRunningCommandAndWaitForInitialOutput(
	ctx context.Context,
	t *testing.T,
	command string,
	args []string,
	waitForOutputToContain string,
	waitForOutputOnFd string, // can be either "stdout" or "stderr"
) {
	t.Helper()

	t.Logf("Starting: %s %s", command, strings.Join(args, " "))

	cmd := exec.CommandContext(ctx, command, args...)

	var stdoutBuf, stderrBuf syncBuffer
	cmd.Stdout = io.MultiWriter(os.Stdout, &stdoutBuf)
	cmd.Stderr = io.MultiWriter(os.Stderr, &stderrBuf)

	var watchOn *syncBuffer
	switch waitForOutputOnFd {
	case "stdout":
		watchOn = &stdoutBuf
	case "stderr":
		watchOn = &stderrBuf
	default:
		t.Fatalf("oops bad argument")
	}

	err := cmd.Start()
	require.NoError(t, err)
	t.Cleanup(func() {
		// If the cancellation of ctx was already scheduled in a t.Cleanup, then this
		// t.Cleanup is registered after the one, so this one will happen first.
		// Cancelling ctx will send SIGKILL, which will act as a backup in case
		// the process ignored this SIGINT.
		err := cmd.Process.Signal(os.Interrupt)
		require.NoError(t, err)
	})

	testlib.RequireEventually(t, func(requireEventually *require.Assertions) {
		t.Logf(`Waiting for %s to emit output: "%s"`, command, waitForOutputToContain)
		requireEventually.Equal(-1, cmd.ProcessState.ExitCode(), "subcommand ended sooner than expected")
		requireEventually.Contains(watchOn.String(), waitForOutputToContain, "expected process to emit output")
	}, 1*time.Minute, 1*time.Second)

	t.Logf("Detected that %s has started successfully", command)
}
