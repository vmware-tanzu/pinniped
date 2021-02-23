// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	authenticationv1 "k8s.io/api/authentication/v1"
	certificatesv1 "k8s.io/api/certificates/v1"
	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/certificate/csr"
	"k8s.io/client-go/util/keyutil"

	identityv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/identity/v1alpha1"
	"go.pinniped.dev/test/library"
)

func TestWhoAmI_Kubeadm(t *testing.T) {
	// use the cluster signing key being available as a proxy for this being a kubeadm cluster
	// we should add more robust logic around skipping clusters based on vendor
	_ = library.IntegrationEnv(t).WithCapability(library.ClusterSigningKeyIsAvailable)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	whoAmI, err := library.NewConciergeClientset(t).IdentityV1alpha1().WhoAmIRequests().
		Create(ctx, &identityv1alpha1.WhoAmIRequest{}, metav1.CreateOptions{})
	require.NoError(t, err)

	// this user info is based off of the bootstrap cert user created by kubeadm
	require.Equal(t,
		&identityv1alpha1.WhoAmIRequest{
			Status: identityv1alpha1.WhoAmIRequestStatus{
				KubernetesUserInfo: identityv1alpha1.KubernetesUserInfo{
					User: identityv1alpha1.UserInfo{
						Username: "kubernetes-admin",
						Groups: []string{
							"system:masters",
							"system:authenticated",
						},
					},
				},
			},
		},
		whoAmI,
	)
}

func TestWhoAmI_ServiceAccount_Legacy(t *testing.T) {
	_ = library.IntegrationEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	kubeClient := library.NewKubernetesClientset(t).CoreV1()

	ns, err := kubeClient.Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-whoami-",
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	defer func() {
		if t.Failed() {
			return
		}
		err := kubeClient.Namespaces().Delete(ctx, ns.Name, metav1.DeleteOptions{})
		require.NoError(t, err)
	}()

	sa, err := kubeClient.ServiceAccounts(ns.Name).Create(ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-whoami-",
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	secret, err := kubeClient.Secrets(ns.Name).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-whoami-",
			Annotations: map[string]string{
				corev1.ServiceAccountNameKey: sa.Name,
			},
		},
		Type: corev1.SecretTypeServiceAccountToken,
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	library.RequireEventuallyWithoutError(t, func() (bool, error) {
		secret, err = kubeClient.Secrets(ns.Name).Get(ctx, secret.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		return len(secret.Data[corev1.ServiceAccountTokenKey]) > 0, nil
	}, 30*time.Second, time.Second)

	saConfig := library.NewAnonymousClientRestConfig(t)
	saConfig.BearerToken = string(secret.Data[corev1.ServiceAccountTokenKey])

	whoAmI, err := library.NewKubeclient(t, saConfig).PinnipedConcierge.IdentityV1alpha1().WhoAmIRequests().
		Create(ctx, &identityv1alpha1.WhoAmIRequest{}, metav1.CreateOptions{})
	require.NoError(t, err)

	// legacy service account tokens do not have any extra info
	require.Equal(t,
		&identityv1alpha1.WhoAmIRequest{
			Status: identityv1alpha1.WhoAmIRequestStatus{
				KubernetesUserInfo: identityv1alpha1.KubernetesUserInfo{
					User: identityv1alpha1.UserInfo{
						Username: "system:serviceaccount:" + ns.Name + ":" + sa.Name,
						UID:      "", // aggregation drops UID: https://github.com/kubernetes/kubernetes/issues/93699
						Groups: []string{
							"system:serviceaccounts",
							"system:serviceaccounts:" + ns.Name,
							"system:authenticated",
						},
					},
				},
			},
		},
		whoAmI,
	)
}

func TestWhoAmI_ServiceAccount_TokenRequest(t *testing.T) {
	_ = library.IntegrationEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	kubeClient := library.NewKubernetesClientset(t).CoreV1()

	ns, err := kubeClient.Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-whoami-",
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	defer func() {
		if t.Failed() {
			return
		}
		err := kubeClient.Namespaces().Delete(ctx, ns.Name, metav1.DeleteOptions{})
		require.NoError(t, err)
	}()

	sa, err := kubeClient.ServiceAccounts(ns.Name).Create(ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-whoami-",
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	_, tokenRequestProbeErr := kubeClient.ServiceAccounts(ns.Name).CreateToken(ctx, sa.Name, &authenticationv1.TokenRequest{}, metav1.CreateOptions{})
	if errors.IsNotFound(tokenRequestProbeErr) && tokenRequestProbeErr.Error() == "the server could not find the requested resource" {
		return // stop test early since the token request API is not enabled on this cluster - other errors are caught below
	}

	pod, err := kubeClient.Pods(ns.Name).Create(ctx, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-whoami-",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "ignored-but-required",
					Image: "does-not-matter",
				},
			},
			ServiceAccountName: sa.Name,
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	tokenRequestBadAudience, err := kubeClient.ServiceAccounts(ns.Name).CreateToken(ctx, sa.Name, &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences: []string{"should-fail-because-wrong-audience"}, // anything that is not an API server audience
			BoundObjectRef: &authenticationv1.BoundObjectReference{
				Kind:       "Pod",
				APIVersion: "",
				Name:       pod.Name,
				UID:        pod.UID,
			},
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	saBadAudConfig := library.NewAnonymousClientRestConfig(t)
	saBadAudConfig.BearerToken = tokenRequestBadAudience.Status.Token

	_, badAudErr := library.NewKubeclient(t, saBadAudConfig).PinnipedConcierge.IdentityV1alpha1().WhoAmIRequests().
		Create(ctx, &identityv1alpha1.WhoAmIRequest{}, metav1.CreateOptions{})
	require.True(t, errors.IsUnauthorized(badAudErr), library.Sdump(badAudErr))

	tokenRequest, err := kubeClient.ServiceAccounts(ns.Name).CreateToken(ctx, sa.Name, &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences: []string{},
			BoundObjectRef: &authenticationv1.BoundObjectReference{
				Kind:       "Pod",
				APIVersion: "",
				Name:       pod.Name,
				UID:        pod.UID,
			},
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	saTokenReqConfig := library.NewAnonymousClientRestConfig(t)
	saTokenReqConfig.BearerToken = tokenRequest.Status.Token

	whoAmITokenReq, err := library.NewKubeclient(t, saTokenReqConfig).PinnipedConcierge.IdentityV1alpha1().WhoAmIRequests().
		Create(ctx, &identityv1alpha1.WhoAmIRequest{}, metav1.CreateOptions{})
	require.NoError(t, err)

	// new service account tokens include the pod info in the extra fields
	require.Equal(t,
		&identityv1alpha1.WhoAmIRequest{
			Status: identityv1alpha1.WhoAmIRequestStatus{
				KubernetesUserInfo: identityv1alpha1.KubernetesUserInfo{
					User: identityv1alpha1.UserInfo{
						Username: "system:serviceaccount:" + ns.Name + ":" + sa.Name,
						UID:      "", // aggregation drops UID: https://github.com/kubernetes/kubernetes/issues/93699
						Groups: []string{
							"system:serviceaccounts",
							"system:serviceaccounts:" + ns.Name,
							"system:authenticated",
						},
						Extra: map[string]identityv1alpha1.ExtraValue{
							"authentication.kubernetes.io/pod-name": {pod.Name},
							"authentication.kubernetes.io/pod-uid":  {string(pod.UID)},
						},
					},
				},
			},
		},
		whoAmITokenReq,
	)
}

func TestWhoAmI_CSR(t *testing.T) {
	// use the cluster signing key being available as a proxy for this not being an EKS cluster
	// we should add more robust logic around skipping clusters based on vendor
	_ = library.IntegrationEnv(t).WithCapability(library.ClusterSigningKeyIsAvailable)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	kubeClient := library.NewKubernetesClientset(t)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	der, err := x509.MarshalECPrivateKey(privateKey)
	require.NoError(t, err)

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: keyutil.ECPrivateKeyBlockType, Bytes: der})

	csrPEM, err := cert.MakeCSR(privateKey, &pkix.Name{
		CommonName:   "panda-man",
		Organization: []string{"living-the-dream", "need-more-sleep"},
	}, nil, nil)
	require.NoError(t, err)

	csrName, csrUID, err := csr.RequestCertificate(
		kubeClient,
		csrPEM,
		"",
		certificatesv1.KubeAPIServerClientSignerName,
		[]certificatesv1.KeyUsage{certificatesv1.UsageClientAuth},
		privateKey,
	)
	require.NoError(t, err)

	defer func() {
		if t.Failed() {
			return
		}
		err := kubeClient.CertificatesV1beta1().CertificateSigningRequests().Delete(ctx, csrName, metav1.DeleteOptions{})
		require.NoError(t, err)
	}()

	// this is a blind update with no resource version checks, which is only safe during tests
	// use the beta CSR API to support older clusters
	_, err = kubeClient.CertificatesV1beta1().CertificateSigningRequests().UpdateApproval(ctx, &certificatesv1beta1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: csrName,
		},
		Status: certificatesv1beta1.CertificateSigningRequestStatus{
			Conditions: []certificatesv1beta1.CertificateSigningRequestCondition{
				{
					Type:   certificatesv1beta1.CertificateApproved,
					Status: corev1.ConditionTrue,
					Reason: "WhoAmICSRTest",
				},
			},
		},
	}, metav1.UpdateOptions{})
	require.NoError(t, err)

	crtPEM, err := csr.WaitForCertificate(ctx, kubeClient, csrName, csrUID)
	require.NoError(t, err)

	csrConfig := library.NewAnonymousClientRestConfig(t)
	csrConfig.CertData = crtPEM
	csrConfig.KeyData = keyPEM

	whoAmI, err := library.NewKubeclient(t, csrConfig).PinnipedConcierge.IdentityV1alpha1().WhoAmIRequests().
		Create(ctx, &identityv1alpha1.WhoAmIRequest{}, metav1.CreateOptions{})
	require.NoError(t, err)

	require.Equal(t,
		&identityv1alpha1.WhoAmIRequest{
			Status: identityv1alpha1.WhoAmIRequestStatus{
				KubernetesUserInfo: identityv1alpha1.KubernetesUserInfo{
					User: identityv1alpha1.UserInfo{
						Username: "panda-man",
						Groups: []string{
							"need-more-sleep",
							"living-the-dream",
							"system:authenticated",
						},
					},
				},
			},
		},
		whoAmI,
	)
}

func TestWhoAmI_Anonymous(t *testing.T) {
	_ = library.IntegrationEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	anonymousConfig := library.NewAnonymousClientRestConfig(t)

	whoAmI, err := library.NewKubeclient(t, anonymousConfig).PinnipedConcierge.IdentityV1alpha1().WhoAmIRequests().
		Create(ctx, &identityv1alpha1.WhoAmIRequest{}, metav1.CreateOptions{})
	require.NoError(t, err)

	// this also asserts that all users, even unauthenticated ones, can call this API when anonymous is enabled
	// this test will need to be skipped when we start running the integration tests against AKS clusters
	require.Equal(t,
		&identityv1alpha1.WhoAmIRequest{
			Status: identityv1alpha1.WhoAmIRequestStatus{
				KubernetesUserInfo: identityv1alpha1.KubernetesUserInfo{
					User: identityv1alpha1.UserInfo{
						Username: "system:anonymous",
						Groups: []string{
							"system:unauthenticated",
						},
					},
				},
			},
		},
		whoAmI,
	)
}

func TestWhoAmI_ImpersonateDirectly(t *testing.T) {
	_ = library.IntegrationEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	impersonationConfig := library.NewClientConfig(t)
	impersonationConfig.Impersonate = rest.ImpersonationConfig{
		UserName: "solaire",
		// need to impersonate system:authenticated directly to support older clusters otherwise we will get RBAC errors below
		Groups: []string{"astora", "lordran", "system:authenticated"},
		Extra: map[string][]string{
			"covenant": {"warrior-of-sunlight"},
			"loves":    {"sun", "co-op"},
		},
	}

	whoAmI, err := library.NewKubeclient(t, impersonationConfig).PinnipedConcierge.IdentityV1alpha1().WhoAmIRequests().
		Create(ctx, &identityv1alpha1.WhoAmIRequest{}, metav1.CreateOptions{})
	require.NoError(t, err)

	require.Equal(t,
		&identityv1alpha1.WhoAmIRequest{
			Status: identityv1alpha1.WhoAmIRequestStatus{
				KubernetesUserInfo: identityv1alpha1.KubernetesUserInfo{
					User: identityv1alpha1.UserInfo{
						Username: "solaire",
						UID:      "", // no way to impersonate UID: https://github.com/kubernetes/kubernetes/issues/93699
						Groups: []string{
							"astora",
							"lordran",
							"system:authenticated", // impersonation will add this implicitly but only in newer clusters
						},
						Extra: map[string]identityv1alpha1.ExtraValue{
							"covenant": {"warrior-of-sunlight"},
							"loves":    {"sun", "co-op"},
						},
					},
				},
			},
		},
		whoAmI,
	)

	impersonationAnonymousConfig := library.NewClientConfig(t)
	impersonationAnonymousConfig.Impersonate.UserName = "system:anonymous"
	// need to impersonate system:unauthenticated directly to support older clusters otherwise we will get RBAC errors below
	impersonationAnonymousConfig.Impersonate.Groups = []string{"system:unauthenticated"}

	whoAmIAnonymous, err := library.NewKubeclient(t, impersonationAnonymousConfig).PinnipedConcierge.IdentityV1alpha1().WhoAmIRequests().
		Create(ctx, &identityv1alpha1.WhoAmIRequest{}, metav1.CreateOptions{})
	require.NoError(t, err)

	require.Equal(t,
		&identityv1alpha1.WhoAmIRequest{
			Status: identityv1alpha1.WhoAmIRequestStatus{
				KubernetesUserInfo: identityv1alpha1.KubernetesUserInfo{
					User: identityv1alpha1.UserInfo{
						Username: "system:anonymous",
						Groups: []string{
							"system:unauthenticated", // impersonation will add this implicitly but only in newer clusters
						},
					},
				},
			},
		},
		whoAmIAnonymous,
	)
}

func TestWhoAmI_ImpersonateViaProxy(t *testing.T) {
	_ = library.IntegrationEnv(t)

	// TODO: add this test after the impersonation proxy is done
	//  this should test all forms of auth understood by the proxy (certs, SA token, token cred req, anonymous, etc)
	//  remember that impersonation does not support UID: https://github.com/kubernetes/kubernetes/issues/93699
}
