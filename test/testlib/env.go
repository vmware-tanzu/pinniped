// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testlib

import (
	"encoding/base64"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"

	authenticationv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
)

type Capability string
type KubeDistro string

const (
	ClusterSigningKeyIsAvailable     Capability = "clusterSigningKeyIsAvailable"
	AnonymousAuthenticationSupported Capability = "anonymousAuthenticationSupported"
	HasExternalLoadBalancerProvider  Capability = "hasExternalLoadBalancerProvider"
	CanReachInternetLDAPPorts        Capability = "canReachInternetLDAPPorts"

	KindDistro KubeDistro = "Kind"
	GKEDistro  KubeDistro = "GKE"
	AKSDistro  KubeDistro = "AKS"
	EKSDistro  KubeDistro = "EKS"
	TKGSDistro KubeDistro = "TKGS"
)

// TestEnv captures all the external parameters consumed by our integration tests.
type TestEnv struct {
	t *testing.T

	skipPodRestartAssertions bool

	ToolsNamespace                 string                                          `json:"toolsNamespace"`
	ConciergeNamespace             string                                          `json:"conciergeNamespace"`
	SupervisorNamespace            string                                          `json:"supervisorNamespace"`
	ConciergeAppName               string                                          `json:"conciergeAppName"`
	SupervisorAppName              string                                          `json:"supervisorAppName"`
	SupervisorServiceName          string                                          `json:"supervisorServiceName"`
	SupervisorCustomLabels         map[string]string                               `json:"supervisorCustomLabels"`
	ConciergeCustomLabels          map[string]string                               `json:"conciergeCustomLabels"`
	KubernetesDistribution         KubeDistro                                      `json:"kubernetesDistribution"`
	Capabilities                   map[Capability]bool                             `json:"capabilities"`
	TestWebhook                    authenticationv1alpha1.WebhookAuthenticatorSpec `json:"testWebhook"`
	SupervisorHTTPSAddress         string                                          `json:"supervisorHttpsAddress"`
	SupervisorHTTPSIngressAddress  string                                          `json:"supervisorHttpsIngressAddress"`
	SupervisorHTTPSIngressCABundle string                                          `json:"supervisorHttpsIngressCABundle"`
	Proxy                          string                                          `json:"proxy"`
	APIGroupSuffix                 string                                          `json:"apiGroupSuffix"`
	ShellContainerImage            string                                          `json:"shellContainer"`

	TestUser struct {
		Token            string   `json:"token"`
		ExpectedUsername string   `json:"expectedUsername"`
		ExpectedGroups   []string `json:"expectedGroups"`
	} `json:"testUser"`

	CLIUpstreamOIDC                   TestOIDCUpstream   `json:"cliOIDCUpstream"`
	SupervisorUpstreamOIDC            TestOIDCUpstream   `json:"supervisorOIDCUpstream"`
	SupervisorUpstreamLDAP            TestLDAPUpstream   `json:"supervisorLDAPUpstream"`
	SupervisorUpstreamActiveDirectory TestLDAPUpstream   `json:"supervisorActiveDirectoryUpstream"`
	SupervisorUpstreamGithub          TestGithubUpstream `json:"supervisorGithubUpstream"`
}

type TestOIDCUpstream struct {
	Issuer           string   `json:"issuer"`
	CABundle         string   `json:"caBundle"`
	AdditionalScopes []string `json:"additionalScopes"`
	UsernameClaim    string   `json:"usernameClaim"`
	GroupsClaim      string   `json:"groupsClaim"`
	ClientID         string   `json:"clientID"`
	ClientSecret     string   `json:"clientSecret"`
	CallbackURL      string   `json:"callback"`
	Username         string   `json:"username"`
	Password         string   `json:"password"`
	ExpectedGroups   []string `json:"expectedGroups"`
}

// InferSupervisorIssuerURL infers the downstream issuer URL from the callback associated with the upstream test client registration.
func (e *TestEnv) InferSupervisorIssuerURL(t *testing.T) *SupervisorIssuer {
	t.Helper()
	supervisorIssuer := NewSupervisorIssuer(t, e.SupervisorUpstreamOIDC.CallbackURL)
	require.True(t, strings.HasSuffix(supervisorIssuer.issuerURL.Path, "/callback"))
	supervisorIssuer.issuerURL.Path = strings.TrimSuffix(supervisorIssuer.issuerURL.Path, "/callback")

	t.Logf("InferSupervisorIssuerURL(): testing with downstream issuer URL %s", supervisorIssuer.Issuer())

	return supervisorIssuer
}

func (e *TestEnv) DefaultTLSCertSecretName() string {
	return e.SupervisorAppName + "-default-tls-certificate"
}

type TestLDAPUpstream struct {
	Host                                            string   `json:"host"`
	Domain                                          string   `json:"domain"`
	StartTLSOnlyHost                                string   `json:"startTLSOnlyHost"`
	CABundle                                        string   `json:"caBundle"`
	BindUsername                                    string   `json:"bindUsername"`
	BindPassword                                    string   `json:"bindPassword"`
	UserSearchBase                                  string   `json:"userSearchBase"`
	DefaultNamingContextSearchBase                  string   `json:"defaultNamingContextSearchBase"`
	GroupSearchBase                                 string   `json:"groupSearchBase"`
	TestUserDN                                      string   `json:"testUserDN"`
	TestUserCN                                      string   `json:"testUserCN"`
	TestUserPassword                                string   `json:"testUserPassword"`
	TestUserMailAttributeName                       string   `json:"testUserMailAttributeName"`
	TestUserMailAttributeValue                      string   `json:"testUserMailAttributeValue"`
	TestUserUniqueIDAttributeName                   string   `json:"testUserUniqueIDAttributeName"`
	TestUserUniqueIDAttributeValue                  string   `json:"testUserUniqueIDAttributeValue"`
	TestUserDirectGroupsCNs                         []string `json:"testUserDirectGroupsCNs"`
	TestUserDirectPosixGroupsCNs                    []string `json:"testUserDirectPosixGroupsCNs"`
	TestUserDirectGroupsDNs                         []string `json:"testUserDirectGroupsDNs"`
	TestUserSAMAccountNameValue                     string   `json:"testUserSAMAccountNameValue"`
	TestUserPrincipalNameValue                      string   `json:"testUserPrincipalNameValue"`
	TestUserIndirectGroupsSAMAccountNames           []string `json:"TestUserIndirectGroupsSAMAccountNames"`
	TestUserIndirectGroupsSAMAccountPlusDomainNames []string `json:"TestUserIndirectGroupsSAMAccountPlusDomainNames"`
	TestDeactivatedUserSAMAccountNameValue          string   `json:"TestDeactivatedUserSAMAccountNameValue"`
	TestDeactivatedUserPassword                     string   `json:"TestDeactivatedUserPassword"`
}

type TestGithubUpstream struct {
	GithubAppClientID                string   `json:"githubAppClientId"` // GitHub's new-style GitHub App
	GithubAppClientSecret            string   `json:"githubAppClientSecret"`
	GithubOAuthAppClientID           string   `json:"githubOAuthAppClientId"` // GitHub's old-style OAuth App
	GithubOAuthAppClientSecret       string   `json:"githubOAuthAppClientSecret"`
	GithubOAuthAppAllowedCallbackURL string   `json:"githubOAuthAppAllowedCallbackURL"` // the callback URL that was configured in GitHub for this App
	TestUserUsername                 string   `json:"testUserUsername"`                 // the "login" attribute value for the user
	TestUserPassword                 string   `json:"testUserPassword"`
	TestUserOTPSecret                string   `json:"testUserOTPSecret"`
	TestUserID                       string   `json:"testUserID"`           // the "id" attribute value for the user
	TestUserOrganization             string   `json:"testUserOrganization"` // an org to which the user belongs
	TestUserExpectedTeamNames        []string `json:"testUserExpectedTeamNames"`
	TestUserExpectedTeamSlugs        []string `json:"testUserExpectedTeamSlugs"`
}

// ProxyEnv returns a set of environment variable strings (e.g., to combine with os.Environ()) which set up the configured test HTTP proxy.
func (e *TestEnv) ProxyEnv() []string {
	if e.Proxy == "" {
		return nil
	}
	return []string{"http_proxy=" + e.Proxy, "https_proxy=" + e.Proxy, "no_proxy=127.0.0.1"}
}

// memoizedTestEnvsByTest maps *testing.T pointers to *TestEnv. It exists so that we don't do all the
// environment parsing N times per test and so that any implicit assertions happen only once.
var memoizedTestEnvsByTest sync.Map //nolint:gochecknoglobals

type TestEnvOption func(env *TestEnv)

// SkipPodRestartAssertions is a functional option that can be passed to IntegrationEnv()
// to skip using the implicit assertions which check that no pods get restarted during tests.
// Please using this sparingly, since most pod restarts are caused by unintentional crashes
// and should therefore cause tests to fail.
func SkipPodRestartAssertions() TestEnvOption {
	return func(t *TestEnv) {
		t.skipPodRestartAssertions = true
		t.t.Log("skipping pod restart assertions for test", t.t.Name())
	}
}

// IntegrationEnv gets the integration test environment from OS environment variables. This
// method also implies SkipUnlessIntegration().
func IntegrationEnv(t *testing.T, opts ...TestEnvOption) *TestEnv {
	if existing, exists := memoizedTestEnvsByTest.Load(t); exists {
		return existing.(*TestEnv)
	}

	t.Helper()
	SkipUnlessIntegration(t)

	capabilitiesDescriptionYAML := os.Getenv("PINNIPED_TEST_CLUSTER_CAPABILITY_YAML")
	capabilitiesDescriptionFile := os.Getenv("PINNIPED_TEST_CLUSTER_CAPABILITY_FILE")
	require.NotEmptyf(t,
		capabilitiesDescriptionYAML+capabilitiesDescriptionFile,
		"must specify either PINNIPED_TEST_CLUSTER_CAPABILITY_YAML or PINNIPED_TEST_CLUSTER_CAPABILITY_FILE env var for integration tests",
	)
	if capabilitiesDescriptionYAML == "" {
		bytes, err := os.ReadFile(capabilitiesDescriptionFile)
		capabilitiesDescriptionYAML = string(bytes)
		require.NoError(t, err)
	}

	var testEnv TestEnv
	err := yaml.Unmarshal([]byte(capabilitiesDescriptionYAML), &testEnv)
	require.NoErrorf(t, err, "capabilities specification was invalid YAML")

	loadEnvVars(t, &testEnv)
	testEnv.t = t

	for _, opt := range opts {
		opt(&testEnv)
	}

	memoizedTestEnvsByTest.Store(t, &testEnv)

	// By default, in every integration test, assert that no pods in our namespaces restart during the test.
	if !testEnv.skipPodRestartAssertions {
		assertNoRestartsDuringTest(t, testEnv.ConciergeNamespace, "!pinniped.dev/test")
		assertNoRestartsDuringTest(t, testEnv.SupervisorNamespace, "!pinniped.dev/test")
	}

	return &testEnv
}

func needEnv(t *testing.T, key string) string {
	t.Helper()
	value := os.Getenv(key)
	require.NotEmptyf(t, value, "must specify %s env var for integration tests", key)
	return value
}

func base64Decoded(t *testing.T, s string) string {
	t.Helper()
	if len(s) == 0 {
		return s
	}
	bytes, err := base64.StdEncoding.DecodeString(s)
	require.NoError(t, err)
	return string(bytes)
}

func wantEnv(key, dephault string) string {
	value, ok := os.LookupEnv(key)
	if !ok {
		return dephault
	}
	return value
}

func filterEmpty(ss []string) []string {
	filtered := []string{}
	for _, s := range ss {
		if len(s) != 0 {
			filtered = append(filtered, s)
		}
	}
	return filtered
}

func loadEnvVars(t *testing.T, result *TestEnv) {
	t.Helper()

	result.ToolsNamespace = os.Getenv("PINNIPED_TEST_TOOLS_NAMESPACE")

	result.ConciergeNamespace = needEnv(t, "PINNIPED_TEST_CONCIERGE_NAMESPACE")
	result.ConciergeAppName = needEnv(t, "PINNIPED_TEST_CONCIERGE_APP_NAME")
	result.TestUser.ExpectedUsername = needEnv(t, "PINNIPED_TEST_USER_USERNAME")
	result.TestUser.ExpectedGroups = strings.Split(strings.ReplaceAll(needEnv(t, "PINNIPED_TEST_USER_GROUPS"), " ", ""), ",")
	result.TestUser.Token = needEnv(t, "PINNIPED_TEST_USER_TOKEN")
	result.TestWebhook.Endpoint = needEnv(t, "PINNIPED_TEST_WEBHOOK_ENDPOINT")
	result.SupervisorNamespace = needEnv(t, "PINNIPED_TEST_SUPERVISOR_NAMESPACE")
	result.SupervisorAppName = needEnv(t, "PINNIPED_TEST_SUPERVISOR_APP_NAME")
	result.SupervisorServiceName = os.Getenv("PINNIPED_TEST_SUPERVISOR_SERVICE_NAME")
	result.TestWebhook.TLS = &authenticationv1alpha1.TLSSpec{CertificateAuthorityData: needEnv(t, "PINNIPED_TEST_WEBHOOK_CA_BUNDLE")}

	result.SupervisorHTTPSIngressAddress = os.Getenv("PINNIPED_TEST_SUPERVISOR_HTTPS_INGRESS_ADDRESS")
	result.SupervisorHTTPSAddress = needEnv(t, "PINNIPED_TEST_SUPERVISOR_HTTPS_ADDRESS")
	result.SupervisorHTTPSIngressCABundle = base64Decoded(t, os.Getenv("PINNIPED_TEST_SUPERVISOR_HTTPS_INGRESS_CA_BUNDLE"))

	conciergeCustomLabelsYAML := needEnv(t, "PINNIPED_TEST_CONCIERGE_CUSTOM_LABELS")
	var conciergeCustomLabels map[string]string
	err := yaml.Unmarshal([]byte(conciergeCustomLabelsYAML), &conciergeCustomLabels)
	require.NoErrorf(t, err, "PINNIPED_TEST_CONCIERGE_CUSTOM_LABELS must be a YAML map of string to string")
	result.ConciergeCustomLabels = conciergeCustomLabels
	require.NotEmpty(t, result.ConciergeCustomLabels, "PINNIPED_TEST_CONCIERGE_CUSTOM_LABELS cannot be empty")
	supervisorCustomLabelsYAML := needEnv(t, "PINNIPED_TEST_SUPERVISOR_CUSTOM_LABELS")
	var supervisorCustomLabels map[string]string
	err = yaml.Unmarshal([]byte(supervisorCustomLabelsYAML), &supervisorCustomLabels)
	require.NoErrorf(t, err, "PINNIPED_TEST_SUPERVISOR_CUSTOM_LABELS must be a YAML map of string to string")
	result.SupervisorCustomLabels = supervisorCustomLabels
	require.NotEmpty(t, result.SupervisorCustomLabels, "PINNIPED_TEST_SUPERVISOR_CUSTOM_LABELS cannot be empty")

	result.Proxy = os.Getenv("PINNIPED_TEST_PROXY")
	result.APIGroupSuffix = wantEnv("PINNIPED_TEST_API_GROUP_SUFFIX", "pinniped.dev")
	result.ShellContainerImage = needEnv(t, "PINNIPED_TEST_SHELL_CONTAINER_IMAGE")

	result.CLIUpstreamOIDC = TestOIDCUpstream{
		Issuer:      needEnv(t, "PINNIPED_TEST_CLI_OIDC_ISSUER"),
		CABundle:    base64Decoded(t, os.Getenv("PINNIPED_TEST_CLI_OIDC_ISSUER_CA_BUNDLE")),
		ClientID:    needEnv(t, "PINNIPED_TEST_CLI_OIDC_CLIENT_ID"),
		CallbackURL: needEnv(t, "PINNIPED_TEST_CLI_OIDC_CALLBACK_URL"),
		Username:    needEnv(t, "PINNIPED_TEST_CLI_OIDC_USERNAME"),
		Password:    needEnv(t, "PINNIPED_TEST_CLI_OIDC_PASSWORD"),
	}

	result.SupervisorUpstreamOIDC = TestOIDCUpstream{
		Issuer:           needEnv(t, "PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_ISSUER"),
		CABundle:         base64Decoded(t, os.Getenv("PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_ISSUER_CA_BUNDLE")),
		AdditionalScopes: filterEmpty(strings.Split(strings.ReplaceAll(os.Getenv("PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_ADDITIONAL_SCOPES"), " ", ""), ",")),
		UsernameClaim:    os.Getenv("PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_USERNAME_CLAIM"),
		GroupsClaim:      os.Getenv("PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_GROUPS_CLAIM"),
		ClientID:         needEnv(t, "PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_CLIENT_ID"),
		ClientSecret:     needEnv(t, "PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_CLIENT_SECRET"),
		CallbackURL:      needEnv(t, "PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_CALLBACK_URL"),
		Username:         needEnv(t, "PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_USERNAME"),
		Password:         needEnv(t, "PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_PASSWORD"),
		ExpectedGroups:   filterEmpty(strings.Split(strings.ReplaceAll(os.Getenv("PINNIPED_TEST_SUPERVISOR_UPSTREAM_OIDC_EXPECTED_GROUPS"), " ", ""), ",")),
	}

	result.SupervisorUpstreamLDAP = TestLDAPUpstream{
		Host:                           needEnv(t, "PINNIPED_TEST_LDAP_HOST"),
		StartTLSOnlyHost:               needEnv(t, "PINNIPED_TEST_LDAP_STARTTLS_ONLY_HOST"),
		CABundle:                       base64Decoded(t, os.Getenv("PINNIPED_TEST_LDAP_LDAPS_CA_BUNDLE")),
		BindUsername:                   needEnv(t, "PINNIPED_TEST_LDAP_BIND_ACCOUNT_USERNAME"),
		BindPassword:                   needEnv(t, "PINNIPED_TEST_LDAP_BIND_ACCOUNT_PASSWORD"),
		UserSearchBase:                 needEnv(t, "PINNIPED_TEST_LDAP_USERS_SEARCH_BASE"),
		GroupSearchBase:                needEnv(t, "PINNIPED_TEST_LDAP_GROUPS_SEARCH_BASE"),
		TestUserDN:                     needEnv(t, "PINNIPED_TEST_LDAP_USER_DN"),
		TestUserCN:                     needEnv(t, "PINNIPED_TEST_LDAP_USER_CN"),
		TestUserUniqueIDAttributeName:  needEnv(t, "PINNIPED_TEST_LDAP_USER_UNIQUE_ID_ATTRIBUTE_NAME"),
		TestUserUniqueIDAttributeValue: needEnv(t, "PINNIPED_TEST_LDAP_USER_UNIQUE_ID_ATTRIBUTE_VALUE"),
		TestUserMailAttributeName:      needEnv(t, "PINNIPED_TEST_LDAP_USER_EMAIL_ATTRIBUTE_NAME"),
		TestUserMailAttributeValue:     needEnv(t, "PINNIPED_TEST_LDAP_USER_EMAIL_ATTRIBUTE_VALUE"),
		TestUserDirectGroupsCNs:        filterEmpty(strings.Split(needEnv(t, "PINNIPED_TEST_LDAP_EXPECTED_DIRECT_GROUPS_CN"), ";")),
		TestUserDirectPosixGroupsCNs:   filterEmpty(strings.Split(needEnv(t, "PINNIPED_TEST_LDAP_EXPECTED_DIRECT_POSIX_GROUPS_CN"), ";")),
		TestUserDirectGroupsDNs:        filterEmpty(strings.Split(needEnv(t, "PINNIPED_TEST_LDAP_EXPECTED_DIRECT_GROUPS_DN"), ";")),
		TestUserPassword:               needEnv(t, "PINNIPED_TEST_LDAP_USER_PASSWORD"),
	}

	result.SupervisorUpstreamActiveDirectory = TestLDAPUpstream{
		Host:                                  wantEnv("PINNIPED_TEST_AD_HOST", ""),
		Domain:                                wantEnv("PINNIPED_TEST_AD_DOMAIN", ""),
		CABundle:                              base64Decoded(t, os.Getenv("PINNIPED_TEST_AD_LDAPS_CA_BUNDLE")),
		BindUsername:                          wantEnv("PINNIPED_TEST_AD_BIND_ACCOUNT_USERNAME", ""),
		BindPassword:                          wantEnv("PINNIPED_TEST_AD_BIND_ACCOUNT_PASSWORD", ""),
		TestUserPassword:                      wantEnv("PINNIPED_TEST_AD_USER_PASSWORD", ""),
		TestUserUniqueIDAttributeName:         wantEnv("PINNIPED_TEST_AD_USER_UNIQUE_ID_ATTRIBUTE_NAME", ""),
		TestUserUniqueIDAttributeValue:        wantEnv("PINNIPED_TEST_AD_USER_UNIQUE_ID_ATTRIBUTE_VALUE", ""),
		TestUserPrincipalNameValue:            wantEnv("PINNIPED_TEST_AD_USER_USER_PRINCIPAL_NAME", ""),
		TestUserMailAttributeValue:            wantEnv("PINNIPED_TEST_AD_USER_EMAIL_ATTRIBUTE_VALUE", ""),
		TestUserMailAttributeName:             wantEnv("PINNIPED_TEST_AD_USER_EMAIL_ATTRIBUTE_NAME", ""),
		TestUserDirectGroupsDNs:               filterEmpty(strings.Split(wantEnv("PINNIPED_TEST_AD_USER_EXPECTED_GROUPS_DN", ""), ";")),
		TestUserDirectGroupsCNs:               filterEmpty(strings.Split(wantEnv("PINNIPED_TEST_AD_USER_EXPECTED_GROUPS_CN", ""), ";")),
		TestUserIndirectGroupsSAMAccountNames: filterEmpty(strings.Split(wantEnv("PINNIPED_TEST_AD_USER_EXPECTED_GROUPS_SAMACCOUNTNAME", ""), ";")),
		TestUserIndirectGroupsSAMAccountPlusDomainNames: filterEmpty(strings.Split(wantEnv("PINNIPED_TEST_AD_USER_EXPECTED_GROUPS_SAMACCOUNTNAME_DOMAINNAMES", ""), ";")),
		TestDeactivatedUserSAMAccountNameValue:          wantEnv("PINNIPED_TEST_DEACTIVATED_AD_USER_SAMACCOUNTNAME", ""),
		TestDeactivatedUserPassword:                     wantEnv("PINNIPED_TEST_DEACTIVATED_AD_USER_PASSWORD", ""),
		DefaultNamingContextSearchBase:                  wantEnv("PINNIPED_TEST_AD_DEFAULTNAMINGCONTEXT_DN", ""),
		UserSearchBase:                                  wantEnv("PINNIPED_TEST_AD_USERS_DN", ""),
		GroupSearchBase:                                 wantEnv("PINNIPED_TEST_AD_USERS_DN", ""),
	}

	result.SupervisorUpstreamGithub = TestGithubUpstream{
		GithubAppClientID:                wantEnv("PINNIPED_TEST_GITHUB_APP_CLIENT_ID", ""),
		GithubAppClientSecret:            wantEnv("PINNIPED_TEST_GITHUB_APP_CLIENT_SECRET", ""),
		GithubOAuthAppClientID:           wantEnv("PINNIPED_TEST_GITHUB_OAUTH_APP_CLIENT_ID", ""),
		GithubOAuthAppClientSecret:       wantEnv("PINNIPED_TEST_GITHUB_OAUTH_APP_CLIENT_SECRET", ""),
		GithubOAuthAppAllowedCallbackURL: wantEnv("PINNIPED_TEST_GITHUB_OAUTH_APP_ALLOWED_CALLBACK_URL", ""),
		TestUserUsername:                 wantEnv("PINNIPED_TEST_GITHUB_USER_USERNAME", ""),
		TestUserPassword:                 wantEnv("PINNIPED_TEST_GITHUB_USER_PASSWORD", ""),
		TestUserOTPSecret:                wantEnv("PINNIPED_TEST_GITHUB_USER_OTP_SECRET", ""),
		TestUserID:                       wantEnv("PINNIPED_TEST_GITHUB_USERID", ""),
		TestUserOrganization:             wantEnv("PINNIPED_TEST_GITHUB_ORG", ""),
		TestUserExpectedTeamNames:        filterEmpty(strings.Split(wantEnv("PINNIPED_TEST_GITHUB_EXPECTED_TEAM_NAMES", ""), ",")),
		TestUserExpectedTeamSlugs:        filterEmpty(strings.Split(wantEnv("PINNIPED_TEST_GITHUB_EXPECTED_TEAM_SLUGS", ""), ",")),
	}

	sort.Strings(result.SupervisorUpstreamLDAP.TestUserDirectGroupsCNs)
	sort.Strings(result.SupervisorUpstreamLDAP.TestUserDirectGroupsDNs)
	sort.Strings(result.SupervisorUpstreamActiveDirectory.TestUserDirectGroupsCNs)
	sort.Strings(result.SupervisorUpstreamActiveDirectory.TestUserDirectGroupsDNs)
	sort.Strings(result.SupervisorUpstreamActiveDirectory.TestUserIndirectGroupsSAMAccountNames)
	sort.Strings(result.SupervisorUpstreamGithub.TestUserExpectedTeamNames)
	sort.Strings(result.SupervisorUpstreamGithub.TestUserExpectedTeamSlugs)
}

func (e *TestEnv) HasCapability(cap Capability) bool {
	e.t.Helper()
	isCapable, capabilityWasDescribed := e.Capabilities[cap]
	require.Truef(e.t, capabilityWasDescribed, "the %q capability of the test environment was not described", cap)
	return isCapable
}

func (e *TestEnv) WithCapability(cap Capability) *TestEnv {
	e.t.Helper()
	if !e.HasCapability(cap) {
		e.t.Skipf("skipping integration test because test environment lacks the %q capability", cap)
	}
	return e
}

func (e *TestEnv) WithoutCapability(cap Capability) *TestEnv {
	e.t.Helper()
	if e.HasCapability(cap) {
		e.t.Skipf("skipping integration test because test environment has the %q capability", cap)
	}
	return e
}

// WithKubeDistribution skips the test unless it will run on the expected cluster type.
// Please use this sparingly. We would prefer that a test run on every cluster type where it can possibly run, so
// prefer to run everywhere when possible or use cluster capabilities when needed, rather than looking at the
// type of cluster to decide to skip a test. However, there are some tests that do not depend on or interact with
// Kubernetes itself which really only need to run on on a single platform to give us the coverage that we desire.
func (e *TestEnv) WithKubeDistribution(distro KubeDistro) *TestEnv {
	e.t.Helper()
	if e.KubernetesDistribution != distro {
		e.t.Skipf("skipping integration test because test environment is running %q but this test wants %q", e.KubernetesDistribution, distro)
	}
	return e
}
