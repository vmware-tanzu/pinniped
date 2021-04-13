// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"

	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/upstreamldap"
)

func TestLDAPSearch(t *testing.T) {
	ctx, cancelFunc := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancelFunc() // this will send SIGKILL to the docker process, just in case
	})

	port := localhostPort(t)
	caBundle := dockerRunLDAPServer(ctx, t, port)

	provider := func(editFunc func(p *upstreamldap.Provider)) *upstreamldap.Provider {
		provider := &upstreamldap.Provider{
			Name:         "test-ldap-provider",
			Host:         "127.0.0.1:" + port,
			CABundle:     caBundle,
			BindUsername: "cn=admin,dc=pinniped,dc=dev",
			BindPassword: "password",
			UserSearch: &upstreamldap.UserSearch{
				Base:              "ou=users,dc=pinniped,dc=dev",
				Filter:            "", // defaults to UsernameAttribute={}, i.e. "cn={}" in this case
				UsernameAttribute: "cn",
				UIDAttribute:      "uidNumber",
			},
		}
		if editFunc != nil {
			editFunc(provider)
		}
		return provider
	}

	pinnyPassword := "password123" // from the LDIF file below
	wallyPassword := "password456" // from the LDIF file below

	tests := []struct {
		name             string
		username         string
		password         string
		provider         *upstreamldap.Provider
		wantError        string
		wantAuthResponse *authenticator.Response
	}{
		{
			name:     "happy path",
			username: "pinny",
			password: pinnyPassword,
			provider: provider(nil),
			wantAuthResponse: &authenticator.Response{
				User: &user.DefaultInfo{Name: "pinny", UID: "1000", Groups: []string{}},
			},
		},
		{
			name:     "happy path as a different user",
			username: "wally",
			password: wallyPassword,
			provider: provider(nil),
			wantAuthResponse: &authenticator.Response{
				User: &user.DefaultInfo{Name: "wally", UID: "1001", Groups: []string{}},
			},
		},
		{
			name:     "using a different user search base",
			username: "pinny",
			password: pinnyPassword,
			provider: provider(func(p *upstreamldap.Provider) { p.UserSearch.Base = "dc=pinniped,dc=dev" }),
			wantAuthResponse: &authenticator.Response{
				User: &user.DefaultInfo{Name: "pinny", UID: "1000", Groups: []string{}},
			},
		},
		{
			name:     "when the user search filter is already wrapped by parenthesis",
			username: "pinny",
			password: pinnyPassword,
			provider: provider(func(p *upstreamldap.Provider) { p.UserSearch.Filter = "(cn={})" }),
			wantAuthResponse: &authenticator.Response{
				User: &user.DefaultInfo{Name: "pinny", UID: "1000", Groups: []string{}},
			},
		},
		{
			name:     "when the UsernameAttribute is dn and a user search filter is provided",
			username: "pinny",
			password: pinnyPassword,
			provider: provider(func(p *upstreamldap.Provider) {
				p.UserSearch.UsernameAttribute = "dn"
				p.UserSearch.Filter = "cn={}"
			}),
			wantAuthResponse: &authenticator.Response{
				User: &user.DefaultInfo{Name: "cn=pinny,ou=users,dc=pinniped,dc=dev", UID: "1000", Groups: []string{}},
			},
		},
		{
			name:     "when the user search filter allows for different ways of logging in and the first one is used",
			username: "pinny",
			password: pinnyPassword,
			provider: provider(func(p *upstreamldap.Provider) {
				p.UserSearch.Filter = "(|(cn={})(mail={}))"
			}),
			wantAuthResponse: &authenticator.Response{
				User: &user.DefaultInfo{Name: "pinny", UID: "1000", Groups: []string{}},
			},
		},
		{
			name:     "when the user search filter allows for different ways of logging in and the second one is used",
			username: "pinny.ldap@example.com",
			password: pinnyPassword,
			provider: provider(func(p *upstreamldap.Provider) {
				p.UserSearch.Filter = "(|(cn={})(mail={}))"
			}),
			wantAuthResponse: &authenticator.Response{
				User: &user.DefaultInfo{Name: "pinny", UID: "1000", Groups: []string{}},
			},
		},
		{
			name:     "when the UIDAttribute is dn",
			username: "pinny",
			password: pinnyPassword,
			provider: provider(func(p *upstreamldap.Provider) { p.UserSearch.UIDAttribute = "dn" }),
			wantAuthResponse: &authenticator.Response{
				User: &user.DefaultInfo{Name: "pinny", UID: "cn=pinny,ou=users,dc=pinniped,dc=dev", Groups: []string{}},
			},
		},
		{
			name:     "when the UIDAttribute is sn",
			username: "pinny",
			password: pinnyPassword,
			provider: provider(func(p *upstreamldap.Provider) { p.UserSearch.UIDAttribute = "sn" }),
			wantAuthResponse: &authenticator.Response{
				User: &user.DefaultInfo{Name: "pinny", UID: "Seal", Groups: []string{}},
			},
		},
		{
			name:     "when the UsernameAttribute is sn",
			username: "seAl", // note that this is not case-sensitive! sn=Seal
			password: pinnyPassword,
			provider: provider(func(p *upstreamldap.Provider) { p.UserSearch.UsernameAttribute = "sn" }),
			wantAuthResponse: &authenticator.Response{
				User: &user.DefaultInfo{Name: "Seal", UID: "1000", Groups: []string{}}, // note that the final answer is case-sensitive
			},
		},
		{
			name:     "when the UsernameAttribute is dn and there is no user search filter provided",
			username: "cn=pinny,ou=users,dc=pinniped,dc=dev",
			password: pinnyPassword,
			provider: provider(func(p *upstreamldap.Provider) {
				p.UserSearch.UsernameAttribute = "dn"
				p.UserSearch.Filter = ""
			}),
			wantError: `must specify UserSearch Filter when UserSearch UsernameAttribute is "dn"`,
		},
		{
			name:      "when the bind user username is not a valid DN",
			username:  "pinny",
			password:  pinnyPassword,
			provider:  provider(func(p *upstreamldap.Provider) { p.BindUsername = "invalid-dn" }),
			wantError: `error binding as "invalid-dn" before user search: LDAP Result Code 34 "Invalid DN Syntax": invalid DN`,
		},
		{
			name:      "when the bind user username is wrong",
			username:  "pinny",
			password:  pinnyPassword,
			provider:  provider(func(p *upstreamldap.Provider) { p.BindUsername = "cn=wrong,dc=pinniped,dc=dev" }),
			wantError: `error binding as "cn=wrong,dc=pinniped,dc=dev" before user search: LDAP Result Code 49 "Invalid Credentials": `,
		},
		{
			name:      "when the bind user password is wrong",
			username:  "pinny",
			password:  pinnyPassword,
			provider:  provider(func(p *upstreamldap.Provider) { p.BindPassword = "wrong-password" }),
			wantError: `error binding as "cn=admin,dc=pinniped,dc=dev" before user search: LDAP Result Code 49 "Invalid Credentials": `,
		},
		{
			name:      "when the end user password is wrong",
			username:  "pinny",
			password:  "wrong-pinny-password",
			provider:  provider(nil),
			wantError: `error binding for user "pinny" using provided password against DN "cn=pinny,ou=users,dc=pinniped,dc=dev": LDAP Result Code 49 "Invalid Credentials": `,
		},
		{
			name:      "when the end user username is wrong",
			username:  "wrong-username",
			password:  pinnyPassword,
			provider:  provider(nil),
			wantError: `searching for user "wrong-username" resulted in 0 search results, but expected 1 result`,
		},
		{
			name:      "when the user search filter does not compile",
			username:  "pinny",
			password:  pinnyPassword,
			provider:  provider(func(p *upstreamldap.Provider) { p.UserSearch.Filter = "*" }),
			wantError: `error searching for user "pinny": LDAP Result Code 201 "Filter Compile Error": ldap: error parsing filter`,
		},
		{
			name:     "when there are too many search results for the user",
			username: "pinny",
			password: pinnyPassword,
			provider: provider(func(p *upstreamldap.Provider) {
				p.UserSearch.Filter = "objectClass=*" // overly broad search filter
			}),
			wantError: `error searching for user "pinny": LDAP Result Code 4 "Size Limit Exceeded": `,
		},
		{
			name:      "when the server is unreachable",
			username:  "pinny",
			password:  pinnyPassword,
			provider:  provider(func(p *upstreamldap.Provider) { p.Host = "127.0.0.1:27534" }), // hopefully this port is not in use on the host running tests
			wantError: `error dialing host "127.0.0.1:27534": LDAP Result Code 200 "Network Error": dial tcp 127.0.0.1:27534: connect: connection refused`,
		},
		{
			name:      "when the server is not parsable",
			username:  "pinny",
			password:  pinnyPassword,
			provider:  provider(func(p *upstreamldap.Provider) { p.Host = "too:many:ports" }),
			wantError: `error dialing host "too:many:ports": LDAP Result Code 200 "Network Error": address too:many:ports: too many colons in address`,
		},
		{
			name:      "when the CA bundle is not parsable",
			username:  "pinny",
			password:  pinnyPassword,
			provider:  provider(func(p *upstreamldap.Provider) { p.CABundle = []byte("invalid-pem") }),
			wantError: fmt.Sprintf(`error dialing host "127.0.0.1:%s": LDAP Result Code 200 "Network Error": could not parse CA bundle`, port),
		},
		{
			name:      "when the CA bundle does not cause the host to be trusted",
			username:  "pinny",
			password:  pinnyPassword,
			provider:  provider(func(p *upstreamldap.Provider) { p.CABundle = nil }),
			wantError: fmt.Sprintf(`error dialing host "127.0.0.1:%s": LDAP Result Code 200 "Network Error": x509: certificate signed by unknown authority`, port),
		},
		{
			name:      "when the UsernameAttribute attribute has multiple values in the entry",
			username:  "wally.ldap@example.com",
			password:  wallyPassword,
			provider:  provider(func(p *upstreamldap.Provider) { p.UserSearch.UsernameAttribute = "mail" }),
			wantError: `found 2 values for attribute "mail" while searching for user "wally.ldap@example.com", but expected 1 result`,
		},
		{
			name:      "when the UIDAttribute attribute has multiple values in the entry",
			username:  "wally",
			password:  wallyPassword,
			provider:  provider(func(p *upstreamldap.Provider) { p.UserSearch.UIDAttribute = "mail" }),
			wantError: `found 2 values for attribute "mail" while searching for user "wally", but expected 1 result`,
		},
		{
			name:     "when the UsernameAttribute attribute is not found in the entry",
			username: "wally",
			password: wallyPassword,
			provider: provider(func(p *upstreamldap.Provider) {
				p.UserSearch.Filter = "cn={}"
				p.UserSearch.UsernameAttribute = "attr-does-not-exist"
			}),
			wantError: `found 0 values for attribute "attr-does-not-exist" while searching for user "wally", but expected 1 result`,
		},
		{
			name:      "when the UIDAttribute attribute is not found in the entry",
			username:  "wally",
			password:  wallyPassword,
			provider:  provider(func(p *upstreamldap.Provider) { p.UserSearch.UIDAttribute = "attr-does-not-exist" }),
			wantError: `found 0 values for attribute "attr-does-not-exist" while searching for user "wally", but expected 1 result`,
		},
		{
			name:      "when the UsernameAttribute has the wrong case",
			username:  "Seal",
			password:  pinnyPassword,
			provider:  provider(func(p *upstreamldap.Provider) { p.UserSearch.UsernameAttribute = "SN" }), // this is case-sensitive
			wantError: `found 0 values for attribute "SN" while searching for user "Seal", but expected 1 result`,
		},
		{
			name:      "when the UIDAttribute has the wrong case",
			username:  "pinny",
			password:  pinnyPassword,
			provider:  provider(func(p *upstreamldap.Provider) { p.UserSearch.UIDAttribute = "SN" }), // this is case-sensitive
			wantError: `found 0 values for attribute "SN" while searching for user "pinny", but expected 1 result`,
		},
		{
			name:     "when the UsernameAttribute is DN and has the wrong case",
			username: "pinny",
			password: pinnyPassword,
			provider: provider(func(p *upstreamldap.Provider) {
				p.UserSearch.UsernameAttribute = "DN" // dn must be lower-case
				p.UserSearch.Filter = "cn={}"
			}),
			wantError: `found 0 values for attribute "DN" while searching for user "pinny", but expected 1 result`,
		},
		{
			name:     "when the UIDAttribute is DN and has the wrong case",
			username: "pinny",
			password: pinnyPassword,
			provider: provider(func(p *upstreamldap.Provider) {
				p.UserSearch.UIDAttribute = "DN" // dn must be lower-case
			}),
			wantError: `found 0 values for attribute "DN" while searching for user "pinny", but expected 1 result`,
		},
		{
			name:      "when the search base is invalid",
			username:  "pinny",
			password:  pinnyPassword,
			provider:  provider(func(p *upstreamldap.Provider) { p.UserSearch.Base = "invalid-base" }),
			wantError: `error searching for user "pinny": LDAP Result Code 34 "Invalid DN Syntax": invalid DN`,
		},
		{
			name:      "when the search base does not exist",
			username:  "pinny",
			password:  pinnyPassword,
			provider:  provider(func(p *upstreamldap.Provider) { p.UserSearch.Base = "ou=does-not-exist,dc=pinniped,dc=dev" }),
			wantError: `error searching for user "pinny": LDAP Result Code 32 "No Such Object": `,
		},
		{
			name:      "when the search base causes no search results",
			username:  "pinny",
			password:  pinnyPassword,
			provider:  provider(func(p *upstreamldap.Provider) { p.UserSearch.Base = "ou=groups,dc=pinniped,dc=dev" }),
			wantError: `searching for user "pinny" resulted in 0 search results, but expected 1 result`,
		},
		{
			name:      "when there is no username specified",
			username:  "",
			password:  pinnyPassword,
			provider:  provider(nil),
			wantError: `searching for user "" resulted in 0 search results, but expected 1 result`,
		},
		{
			name:      "when there is no password specified",
			username:  "pinny",
			password:  "",
			provider:  provider(nil),
			wantError: `error binding for user "pinny" using provided password against DN "cn=pinny,ou=users,dc=pinniped,dc=dev": LDAP Result Code 206 "Empty password not allowed by the client": ldap: empty password not allowed by the client`,
		},
		{
			name:      "when the user has no password in their entry",
			username:  "olive",
			password:  "anything",
			provider:  provider(nil),
			wantError: `error binding for user "olive" using provided password against DN "cn=olive,ou=users,dc=pinniped,dc=dev": LDAP Result Code 49 "Invalid Credentials": `,
		},
	}

	for _, test := range tests {
		tt := test
		t.Run(tt.name, func(t *testing.T) {
			authResponse, authenticated, err := tt.provider.AuthenticateUser(ctx, tt.username, tt.password)

			if tt.wantError != "" {
				require.EqualError(t, err, tt.wantError)
				require.False(t, authenticated)
				require.Nil(t, authResponse)
			} else {
				require.NoError(t, err)
				require.True(t, authenticated)
				require.Equal(t, tt.wantAuthResponse, authResponse)
			}
		})
	}
}

func localhostPort(t *testing.T) string {
	t.Helper()

	unusedPortGrabbingListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	recentlyClaimedHostAndPort := unusedPortGrabbingListener.Addr().String()
	require.NoError(t, unusedPortGrabbingListener.Close())

	splitHostAndPort := strings.Split(recentlyClaimedHostAndPort, ":")
	require.Len(t, splitHostAndPort, 2)

	return splitHostAndPort[1]
}

func dockerRunLDAPServer(ctx context.Context, t *testing.T, hostPort string) []byte {
	t.Helper()

	_, err := exec.LookPath("docker")
	require.NoError(t, err)

	ca, err := certauthority.New("Test LDAP CA", time.Hour*24)
	require.NoError(t, err)

	certPEM, keyPEM, err := ca.IssueServerCertPEM(nil, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour*24)
	require.NoError(t, err)

	tempDir, err := ioutil.TempDir("", "pinniped-test-*")
	require.NoError(t, err)
	t.Cleanup(func() {
		err := os.Remove(tempDir)
		require.NoError(t, err)
	})

	writeToNewTempFile(t, tempDir, "cert.pem", certPEM)
	writeToNewTempFile(t, tempDir, "key.pem", keyPEM)
	writeToNewTempFile(t, tempDir, "ca.pem", ca.Bundle())
	writeToNewTempFile(t, tempDir, "test.ldif", []byte(testLDIF))

	dockerArgs := []string{
		"run",
		"-e", "BITNAMI_DEBUG=true",
		"-e", "LDAP_ADMIN_USERNAME=admin",
		"-e", "LDAP_ADMIN_PASSWORD=password",
		"-e", "LDAP_ENABLE_TLS=yes",
		"-e", "LDAP_TLS_CERT_FILE=/inputs/cert.pem",
		"-e", "LDAP_TLS_KEY_FILE=/inputs/key.pem",
		"-e", "LDAP_TLS_CA_FILE=/inputs/ca.pem",
		"-e", "LDAP_CUSTOM_LDIF_DIR=/inputs",
		"-e", "LDAP_ROOT=dc=pinniped,dc=dev",
		"-v", tempDir + ":/inputs",
		"-p", hostPort + ":1636",
		"-m", "64m",
		"--rm", // automatically delete the container when finished
		"docker.io/bitnami/openldap",
	}

	t.Log("Starting:", "docker", strings.Join(dockerArgs, " "))

	cmd := exec.CommandContext(ctx, "docker", dockerArgs...)

	var stdoutBuf, stderrBuf syncBuffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	cmd.Stdout = io.MultiWriter(os.Stdout, &stdoutBuf)
	cmd.Stderr = io.MultiWriter(os.Stderr, &stderrBuf)

	err = cmd.Start()
	require.NoError(t, err)
	t.Cleanup(func() {
		// docker requires an interrupt signal to end the container.
		// This t.Cleanup is registered after the one that cancels the context, so this one will happen first.
		err := cmd.Process.Signal(os.Interrupt)
		require.NoError(t, err)
		time.Sleep(time.Second) // give a moment before we move on, because we'll send SIGKILL in a later t.Cleanup
	})

	earlyTerminationCh := make(chan bool, 1)
	go func() {
		err = cmd.Wait()
		earlyTerminationCh <- true
	}()

	terminatedEarly := false
	require.Eventually(t, func() bool {
		t.Log("Waiting for slapd to start...")
		// This substring is contained in the last line of output before the server starts.
		if strings.Contains(stderrBuf.String(), " slapd starting\n") {
			return true
		}
		select {
		case <-earlyTerminationCh:
			terminatedEarly = true
			return true
		default: // ignore when this non-blocking read found no message
		}
		return false
	}, 2*time.Minute, time.Second)

	require.Falsef(t, terminatedEarly, "docker command ended sooner than expected")

	t.Log("Detected LDAP server has started successfully")
	return ca.Bundle()
}

func writeToNewTempFile(t *testing.T, dir string, filename string, contents []byte) {
	t.Helper()

	filePath := path.Join(dir, filename)

	err := ioutil.WriteFile(filePath, contents, 0644)
	require.NoError(t, err)

	t.Cleanup(func() {
		err := os.Remove(filePath)
		require.NoError(t, err)
	})
}

var testLDIF = `
# ** CAUTION: Blank lines separate entries in the LDIF format! Do not remove them! ***
# Here's a good explaination of LDIF:
# https://www.digitalocean.com/community/tutorials/how-to-use-ldif-files-to-make-changes-to-an-openldap-system

# pinniped.dev (organization, root)
dn: dc=pinniped,dc=dev
objectClass: dcObject
objectClass: organization
dc: pinniped
o: example

# users, pinniped.dev (organization unit)
dn: ou=users,dc=pinniped,dc=dev
objectClass: organizationalUnit
ou: users

# groups, pinniped.dev (organization unit)
dn: ou=groups,dc=pinniped,dc=dev
objectClass: organizationalUnit
ou: groups

# beach-groups, groups, pinniped.dev (organization unit)
dn: ou=beach-groups,ou=groups,dc=pinniped,dc=dev
objectClass: organizationalUnit
ou: beach-groups

# pinny, users, pinniped.dev (user)
dn: cn=pinny,ou=users,dc=pinniped,dc=dev
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
cn: pinny
sn: Seal
givenName: Pinny
mail: pinny.ldap@example.com
userPassword: password123
uid: pinny
uidNumber: 1000
gidNumber: 1000
homeDirectory: /home/pinny
loginShell: /bin/bash
gecos: pinny-the-seal

# wally, users, pinniped.dev
dn: cn=wally,ou=users,dc=pinniped,dc=dev
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
cn: wally
sn: Walrus
givenName: Wally
mail: wally.ldap@example.com
mail: wally.alternate@example.com
userPassword: password456
uid: wally
uidNumber: 1001
gidNumber: 1001
homeDirectory: /home/wally
loginShell: /bin/bash
gecos: wally-the-walrus

# olive, users, pinniped.dev (user without password)
dn: cn=olive,ou=users,dc=pinniped,dc=dev
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
cn: olive
sn: Boston Terrier
givenName: Olive
mail: olive.ldap@example.com
uid: olive
uidNumber: 1002
gidNumber: 1002
homeDirectory: /home/olive
loginShell: /bin/bash
gecos: olive-the-dog

# ball-game-players, beach-groups, groups, pinniped.dev (group of users)
dn: cn=ball-game-players,ou=beach-groups,ou=groups,dc=pinniped,dc=dev
cn: ball-game-players
objectClass: groupOfNames
member: cn=pinny,ou=users,dc=pinniped,dc=dev
member: cn=olive,ou=users,dc=pinniped,dc=dev

# seals, groups, pinniped.dev (group of users)
dn: cn=seals,ou=groups,dc=pinniped,dc=dev
cn: seals
objectClass: groupOfNames
member: cn=pinny,ou=users,dc=pinniped,dc=dev

# walruses, groups, pinniped.dev (group of users)
dn: cn=walruses,ou=groups,dc=pinniped,dc=dev
cn: walruses
objectClass: groupOfNames
member: cn=wally,ou=users,dc=pinniped,dc=dev

# pinnipeds, users, pinniped.dev (group of groups)
dn: cn=pinnipeds,ou=groups,dc=pinniped,dc=dev
cn: pinnipeds
objectClass: groupOfNames
member: cn=seals,ou=groups,dc=pinniped,dc=dev
member: cn=walruses,ou=groups,dc=pinniped,dc=dev

# mammals, groups, pinniped.dev (group of both groups and users)
dn: cn=mammals,ou=groups,dc=pinniped,dc=dev
cn: mammals
objectClass: groupOfNames
member: cn=pinninpeds,ou=groups,dc=pinniped,dc=dev
member: cn=olive,ou=users,dc=pinniped,dc=dev
`
