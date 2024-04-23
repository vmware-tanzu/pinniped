// Copyright 2022-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package testlib

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/encoding/unicode"

	"go.pinniped.dev/internal/crypto/ptls"
)

// CreateFreshADTestUser creates a fresh test user in AD to use for this test
// and returns their username and password.
func CreateFreshADTestUser(t *testing.T, env *TestEnv) (string, string) {
	t.Helper()
	// dial tls
	conn := dialTLS(t, env)
	// bind
	err := conn.Bind(env.SupervisorUpstreamActiveDirectory.BindUsername, env.SupervisorUpstreamActiveDirectory.BindPassword)
	require.NoError(t, err)

	testUserName := "user-" + createRandomHexString(t, 7) // sAMAccountNames are limited to 20 characters, so this is as long as we can make it.
	// create
	userDN := fmt.Sprintf("CN=%s,OU=test-users,%s", testUserName, env.SupervisorUpstreamActiveDirectory.UserSearchBase)
	a := ldap.NewAddRequest(userDN, []ldap.Control{})
	a.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
	a.Attribute("userPrincipalName", []string{fmt.Sprintf("%s@%s", testUserName, env.SupervisorUpstreamActiveDirectory.Domain)})
	a.Attribute("sAMAccountName", []string{testUserName})

	err = conn.Add(a)
	require.NoError(t, err)

	// Now that it has been created, schedule it for cleanup.
	t.Cleanup(func() {
		deleteTestADUser(t, env, testUserName)
	})

	// modify password and enable account
	testUserPassword := createRandomASCIIString(t, 20)
	enc := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
	encodedTestUserPassword, err := enc.String("\"" + testUserPassword + "\"")
	require.NoError(t, err)

	m := ldap.NewModifyRequest(userDN, []ldap.Control{})
	m.Replace("unicodePwd", []string{encodedTestUserPassword})
	m.Replace("userAccountControl", []string{"512"})
	err = conn.Modify(m)
	require.NoError(t, err)

	time.Sleep(20 * time.Second) // intrasite domain controller replication can take up to 15 seconds, so wait to ensure the change has propogated.
	return testUserName, testUserPassword
}

// CreateFreshADTestGroup creates a fresh test group in AD to use for this test
// and returns the group's name.
func CreateFreshADTestGroup(t *testing.T, env *TestEnv) string {
	t.Helper()
	// dial tls
	conn := dialTLS(t, env)
	// bind
	err := conn.Bind(env.SupervisorUpstreamActiveDirectory.BindUsername, env.SupervisorUpstreamActiveDirectory.BindPassword)
	require.NoError(t, err)

	// group is domain local and a security group.
	groupType := 0x00000004 | 0x80000000
	// the group is modifiable.
	instanceType := 0x00000004
	testGroupName := "group-" + createRandomHexString(t, 7) // sAMAccountNames are limited to 20 characters, so this is as long as we can make it.
	groupDN := fmt.Sprintf("CN=%s,OU=test-users,%s", testGroupName, env.SupervisorUpstreamActiveDirectory.UserSearchBase)
	a := ldap.NewAddRequest(groupDN, []ldap.Control{})
	a.Attribute("objectClass", []string{"top", "group"})
	a.Attribute("name", []string{testGroupName})
	a.Attribute("sAMAccountName", []string{testGroupName})
	a.Attribute("groupType", []string{fmt.Sprintf("%d", groupType)})
	a.Attribute("instanceType", []string{fmt.Sprintf("%d", instanceType)})
	err = conn.Add(a)
	require.NoError(t, err)

	// Now that it has been created, schedule it for cleanup.
	t.Cleanup(func() {
		deleteTestADUser(t, env, testGroupName)
	})

	time.Sleep(20 * time.Second) // intrasite domain controller replication can take up to 15 seconds, so wait to ensure the change has propogated.
	return testGroupName
}

// AddTestUserToGroup adds a test user to a group within the test-users directory.
func AddTestUserToGroup(t *testing.T, env *TestEnv, testGroupName, testUserName string) {
	t.Helper()

	conn := dialTLS(t, env)
	err := conn.Bind(env.SupervisorUpstreamActiveDirectory.BindUsername, env.SupervisorUpstreamActiveDirectory.BindPassword)
	require.NoError(t, err)

	userDN := fmt.Sprintf("CN=%s,OU=test-users,%s", testUserName, env.SupervisorUpstreamActiveDirectory.UserSearchBase)
	groupDN := fmt.Sprintf("CN=%s,OU=test-users,%s", testGroupName, env.SupervisorUpstreamActiveDirectory.UserSearchBase)

	r := ldap.NewModifyRequest(groupDN, []ldap.Control{})
	r.Add("member", []string{userDN})
	err = conn.Modify(r)
	require.NoError(t, err)
	time.Sleep(20 * time.Second) // intrasite domain controller replication can take up to 15 seconds, so wait to ensure the change has propogated.
}

// DeactivateADTestUser deactivates the test user.
func DeactivateADTestUser(t *testing.T, env *TestEnv, testUserName string) {
	conn := dialTLS(t, env)
	// bind
	err := conn.Bind(env.SupervisorUpstreamActiveDirectory.BindUsername, env.SupervisorUpstreamActiveDirectory.BindPassword)
	require.NoError(t, err)

	userDN := fmt.Sprintf("CN=%s,OU=test-users,%s", testUserName, env.SupervisorUpstreamActiveDirectory.UserSearchBase)
	m := ldap.NewModifyRequest(userDN, []ldap.Control{})
	m.Replace("userAccountControl", []string{"514"}) // normal user, account disabled
	err = conn.Modify(m)
	require.NoError(t, err)

	time.Sleep(20 * time.Second) // intrasite domain controller replication can take up to 15 seconds, so wait to ensure the change has propogated.
}

// LockADTestUser locks the test user's account by entering the wrong password a bunch of times.
func LockADTestUser(t *testing.T, env *TestEnv, testUserName string) {
	userDN := fmt.Sprintf("CN=%s,OU=test-users,%s", testUserName, env.SupervisorUpstreamActiveDirectory.UserSearchBase)
	conn := dialTLS(t, env)

	// our password policy allows 20 wrong attempts before locking the account, so do 21.
	// these wrong password attempts could go to different domain controllers, but account
	// lockout changes are urgently replicated, meaning that the domain controllers will be
	// synced asap rather than in the usual 15 second interval.
	// See https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc961787(v=technet.10)#urgent-replication-of-account-lockout-changes
	for i := 0; i <= 21; i++ {
		err := conn.Bind(userDN, "not-the-right-password-"+fmt.Sprint(i))
		require.Error(t, err) // this should be an error
	}

	err := conn.Bind(env.SupervisorUpstreamActiveDirectory.BindUsername, env.SupervisorUpstreamActiveDirectory.BindPassword)
	require.NoError(t, err)

	time.Sleep(20 * time.Second) // intrasite domain controller replication can take up to 15 seconds, so wait to ensure the change has propogated.
}

// ChangeADTestUserPassword changes the user's password to a new one.
func ChangeADTestUserPassword(t *testing.T, env *TestEnv, testUserName string) {
	conn := dialTLS(t, env)
	// bind
	err := conn.Bind(env.SupervisorUpstreamActiveDirectory.BindUsername, env.SupervisorUpstreamActiveDirectory.BindPassword)
	require.NoError(t, err)

	newTestUserPassword := createRandomASCIIString(t, 20)
	enc := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
	encodedTestUserPassword, err := enc.String(`"` + newTestUserPassword + `"`)
	require.NoError(t, err)

	userDN := fmt.Sprintf("CN=%s,OU=test-users,%s", testUserName, env.SupervisorUpstreamActiveDirectory.UserSearchBase)
	m := ldap.NewModifyRequest(userDN, []ldap.Control{})
	m.Replace("unicodePwd", []string{encodedTestUserPassword})
	err = conn.Modify(m)
	require.NoError(t, err)

	time.Sleep(20 * time.Second) // intrasite domain controller replication can take up to 15 seconds, so wait to ensure the change has propogated.
	// don't bother to return the new password... we won't be using it, just checking that it's changed.
}

// deleteTestADUser deletes the test user created for this test.
func deleteTestADUser(t *testing.T, env *TestEnv, testUserName string) {
	t.Helper()
	conn := dialTLS(t, env)
	// bind
	err := conn.Bind(env.SupervisorUpstreamActiveDirectory.BindUsername, env.SupervisorUpstreamActiveDirectory.BindPassword)
	require.NoError(t, err)

	userDN := fmt.Sprintf("CN=%s,OU=test-users,%s", testUserName, env.SupervisorUpstreamActiveDirectory.UserSearchBase)
	d := ldap.NewDelRequest(userDN, []ldap.Control{})
	err = conn.Del(d)
	require.NoError(t, err)
}

func dialTLS(t *testing.T, env *TestEnv) *ldap.Conn {
	t.Helper()
	// dial tls
	rootCAs := x509.NewCertPool()
	success := rootCAs.AppendCertsFromPEM([]byte(env.SupervisorUpstreamActiveDirectory.CABundle))
	require.True(t, success)
	tlsConfig := ptls.DefaultLDAP(rootCAs)
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: time.Minute}, Config: tlsConfig}
	c, err := dialer.DialContext(context.Background(), "tcp", env.SupervisorUpstreamActiveDirectory.Host)
	require.NoError(t, err)
	conn := ldap.NewConn(c, true)
	conn.Start() //nolint:staticcheck // will need a different approach soon
	return conn
}

func createRandomHexString(t *testing.T, length int) string {
	t.Helper()
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	require.NoError(t, err)
	randomString := hex.EncodeToString(bytes)
	return randomString
}

func createRandomASCIIString(t *testing.T, length int) string {
	result := ""
	for {
		if len(result) >= length {
			return result
		}
		num, err := rand.Int(rand.Reader, big.NewInt(int64(127)))
		require.NoError(t, err)
		n := num.Int64()
		// Make sure that the number/byte/letter is inside
		// the range of printable ASCII characters (excluding space and DEL)
		if n > 32 && n < 127 {
			result += string(rune(n))
		}
	}
}
