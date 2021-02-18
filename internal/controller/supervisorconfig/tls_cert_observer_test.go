// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package supervisorconfig

import (
	"context"
	"crypto/tls"
	"io/ioutil"
	"net/url"
	"testing"
	"time"

	"github.com/sclevine/spec"
	"github.com/sclevine/spec/report"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeinformers "k8s.io/client-go/informers"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"

	"go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/fake"
	pinnipedinformers "go.pinniped.dev/generated/latest/client/supervisor/informers/externalversions"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/testutil"
)

func TestTLSCertObserverControllerInformerFilters(t *testing.T) {
	spec.Run(t, "informer filters", func(t *testing.T, when spec.G, it spec.S) {
		var (
			r                              *require.Assertions
			observableWithInformerOption   *testutil.ObservableWithInformerOption
			secretsInformerFilter          controllerlib.Filter
			federationDomainInformerFilter controllerlib.Filter
		)

		it.Before(func() {
			r = require.New(t)
			observableWithInformerOption = testutil.NewObservableWithInformerOption()
			secretsInformer := kubeinformers.NewSharedInformerFactory(nil, 0).Core().V1().Secrets()
			federationDomainInformer := pinnipedinformers.NewSharedInformerFactory(nil, 0).Config().V1alpha1().FederationDomains()
			_ = NewTLSCertObserverController(
				nil,
				"", // don't care about the secret name for this test
				secretsInformer,
				federationDomainInformer,
				observableWithInformerOption.WithInformer, // make it possible to observe the behavior of the Filters
			)
			secretsInformerFilter = observableWithInformerOption.GetFilterForInformer(secretsInformer)
			federationDomainInformerFilter = observableWithInformerOption.GetFilterForInformer(federationDomainInformer)
		})

		when("watching Secret objects", func() {
			var (
				subject             controllerlib.Filter
				secret, otherSecret *corev1.Secret
			)

			it.Before(func() {
				subject = secretsInformerFilter
				secret = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "any-name", Namespace: "any-namespace"}, Type: corev1.SecretTypeTLS}
				otherSecret = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "any-other-name", Namespace: "any-other-namespace"}, Type: "other type"}
			})

			when("any Secret of type TLS changes", func() {
				it("returns true to trigger the sync method", func() {
					r.True(subject.Add(secret))
					r.True(subject.Update(secret, otherSecret))
					r.True(subject.Update(otherSecret, secret))
					r.True(subject.Delete(secret))
				})
			})

			when("any Secret that is not of type TLS changes", func() {
				it("returns false to avoid triggering the sync method", func() {
					r.False(subject.Add(otherSecret))
					r.False(subject.Update(otherSecret, otherSecret))
					r.False(subject.Delete(otherSecret))
				})
			})
		})

		when("watching FederationDomain objects", func() {
			var (
				subject                 controllerlib.Filter
				provider, otherProvider *v1alpha1.FederationDomain
			)

			it.Before(func() {
				subject = federationDomainInformerFilter
				provider = &v1alpha1.FederationDomain{ObjectMeta: metav1.ObjectMeta{Name: "any-name", Namespace: "any-namespace"}}
				otherProvider = &v1alpha1.FederationDomain{ObjectMeta: metav1.ObjectMeta{Name: "any-other-name", Namespace: "any-other-namespace"}}
			})

			when("any FederationDomain changes", func() {
				it("returns true to trigger the sync method", func() {
					r.True(subject.Add(provider))
					r.True(subject.Update(provider, otherProvider))
					r.True(subject.Update(otherProvider, provider))
					r.True(subject.Delete(provider))
				})
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}

type fakeIssuerTLSCertSetter struct {
	setIssuerHostToTLSCertMapWasCalled bool
	setDefaultTLSCertWasCalled         bool
	issuerHostToTLSCertMapReceived     map[string]*tls.Certificate
	setDefaultTLSCertReceived          *tls.Certificate
}

func (f *fakeIssuerTLSCertSetter) SetIssuerHostToTLSCertMap(issuerHostToTLSCertMap map[string]*tls.Certificate) {
	f.setIssuerHostToTLSCertMapWasCalled = true
	f.issuerHostToTLSCertMapReceived = issuerHostToTLSCertMap
}

func (f *fakeIssuerTLSCertSetter) SetDefaultTLSCert(certificate *tls.Certificate) {
	f.setDefaultTLSCertWasCalled = true
	f.setDefaultTLSCertReceived = certificate
}

func TestTLSCertObserverControllerSync(t *testing.T) {
	spec.Run(t, "Sync", func(t *testing.T, when spec.G, it spec.S) {
		const (
			installedInNamespace = "some-namespace"
			defaultTLSSecretName = "some-default-secret-name"
		)

		var (
			r                      *require.Assertions
			subject                controllerlib.Controller
			pinnipedInformerClient *pinnipedfake.Clientset
			kubeInformerClient     *kubernetesfake.Clientset
			pinnipedInformers      pinnipedinformers.SharedInformerFactory
			kubeInformers          kubeinformers.SharedInformerFactory
			timeoutContext         context.Context
			timeoutContextCancel   context.CancelFunc
			syncContext            *controllerlib.Context
			issuerTLSCertSetter    *fakeIssuerTLSCertSetter
		)

		// Defer starting the informers until the last possible moment so that the
		// nested Before's can keep adding things to the informer caches.
		var startInformersAndController = func() {
			// Set this at the last second to allow for injection of server override.
			subject = NewTLSCertObserverController(
				issuerTLSCertSetter,
				defaultTLSSecretName,
				kubeInformers.Core().V1().Secrets(),
				pinnipedInformers.Config().V1alpha1().FederationDomains(),
				controllerlib.WithInformer,
			)

			// Set this at the last second to support calling subject.Name().
			syncContext = &controllerlib.Context{
				Context: timeoutContext,
				Name:    subject.Name(),
				Key: controllerlib.Key{
					Namespace: installedInNamespace,
					Name:      "any-name",
				},
			}

			// Must start informers before calling TestRunSynchronously()
			kubeInformers.Start(timeoutContext.Done())
			pinnipedInformers.Start(timeoutContext.Done())
			controllerlib.TestRunSynchronously(t, subject)
		}

		var readTestFile = func(path string) []byte {
			data, err := ioutil.ReadFile(path)
			r.NoError(err)
			return data
		}

		it.Before(func() {
			r = require.New(t)

			timeoutContext, timeoutContextCancel = context.WithTimeout(context.Background(), time.Second*3)

			kubeInformerClient = kubernetesfake.NewSimpleClientset()
			kubeInformers = kubeinformers.NewSharedInformerFactory(kubeInformerClient, 0)
			pinnipedInformerClient = pinnipedfake.NewSimpleClientset()
			pinnipedInformers = pinnipedinformers.NewSharedInformerFactory(pinnipedInformerClient, 0)
			issuerTLSCertSetter = &fakeIssuerTLSCertSetter{}

			unrelatedSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some other unrelated secret",
					Namespace: installedInNamespace,
				},
			}
			r.NoError(kubeInformerClient.Tracker().Add(unrelatedSecret))
		})

		it.After(func() {
			timeoutContextCancel()
		})

		when("there are no FederationDomains and no TLS Secrets yet", func() {
			it("sets the issuerTLSCertSetter's map to be empty", func() {
				startInformersAndController()
				err := controllerlib.TestSync(t, subject, *syncContext)
				r.NoError(err)

				r.True(issuerTLSCertSetter.setIssuerHostToTLSCertMapWasCalled)
				r.Empty(issuerTLSCertSetter.issuerHostToTLSCertMapReceived)
				r.True(issuerTLSCertSetter.setDefaultTLSCertWasCalled)
				r.Nil(issuerTLSCertSetter.setDefaultTLSCertReceived)
			})
		})

		when("there are FederationDomains where some have corresponding TLS Secrets and some don't", func() {
			var (
				expectedCertificate1, expectedCertificate2 tls.Certificate
			)

			it.Before(func() {
				var err error
				federationDomainWithoutSecret1 := &v1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "no-secret-federationdomain1",
						Namespace: installedInNamespace,
					},
					Spec: v1alpha1.FederationDomainSpec{Issuer: "https://no-secret-issuer1.com"}, // no SNICertificateSecretName field
				}
				federationDomainWithoutSecret2 := &v1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "no-secret-federationdomain2",
						Namespace: installedInNamespace,
					},
					Spec: v1alpha1.FederationDomainSpec{
						Issuer: "https://no-secret-issuer2.com",
						TLS:    &v1alpha1.FederationDomainTLSSpec{SecretName: ""},
					},
				}
				federationDomainWithBadSecret := &v1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "bad-secret-federationdomain",
						Namespace: installedInNamespace,
					},
					Spec: v1alpha1.FederationDomainSpec{
						Issuer: "https://bad-secret-issuer.com",
						TLS:    &v1alpha1.FederationDomainTLSSpec{SecretName: "bad-tls-secret-name"},
					},
				}
				// Also add one with a URL that cannot be parsed to make sure that the controller is not confused by invalid URLs.
				invalidIssuerURL := ":/host//path"
				_, err = url.Parse(invalidIssuerURL) //nolint:staticcheck // Yes, this URL is intentionally invalid.
				r.Error(err)
				federationDomainWithBadIssuer := &v1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "bad-issuer-federationdomain",
						Namespace: installedInNamespace,
					},
					Spec: v1alpha1.FederationDomainSpec{Issuer: invalidIssuerURL},
				}
				federationDomainWithGoodSecret1 := &v1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "good-secret-federationdomain1",
						Namespace: installedInNamespace,
					},
					// Issuer hostname should be treated in a case-insensitive way and SNI ignores port numbers. Test without a port number.
					Spec: v1alpha1.FederationDomainSpec{
						Issuer: "https://www.iSSuer-wiTh-goOd-secRet1.cOm/path",
						TLS:    &v1alpha1.FederationDomainTLSSpec{SecretName: "good-tls-secret-name1"},
					},
				}
				federationDomainWithGoodSecret2 := &v1alpha1.FederationDomain{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "good-secret-federationdomain2",
						Namespace: installedInNamespace,
					},
					// Issuer hostname should be treated in a case-insensitive way and SNI ignores port numbers. Test with a port number.
					Spec: v1alpha1.FederationDomainSpec{
						Issuer: "https://www.issUEr-WIth-gOOd-seCret2.com:1234/path",
						TLS:    &v1alpha1.FederationDomainTLSSpec{SecretName: "good-tls-secret-name2"},
					},
				}
				testCrt1 := readTestFile("testdata/test.crt")
				r.NotEmpty(testCrt1)
				testCrt2 := readTestFile("testdata/test2.crt")
				r.NotEmpty(testCrt2)
				testKey1 := readTestFile("testdata/test.key")
				r.NotEmpty(testKey1)
				testKey2 := readTestFile("testdata/test2.key")
				r.NotEmpty(testKey2)
				expectedCertificate1, err = tls.X509KeyPair(testCrt1, testKey1)
				r.NoError(err)
				expectedCertificate2, err = tls.X509KeyPair(testCrt2, testKey2)
				r.NoError(err)
				goodTLSSecret1 := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "good-tls-secret-name1", Namespace: installedInNamespace},
					Data:       map[string][]byte{"tls.crt": testCrt1, "tls.key": testKey1},
				}
				goodTLSSecret2 := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "good-tls-secret-name2", Namespace: installedInNamespace},
					Data:       map[string][]byte{"tls.crt": testCrt2, "tls.key": testKey2},
				}
				badTLSSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "bad-tls-secret-name", Namespace: installedInNamespace},
					Data:       map[string][]byte{"junk": nil},
				}
				r.NoError(pinnipedInformerClient.Tracker().Add(federationDomainWithoutSecret1))
				r.NoError(pinnipedInformerClient.Tracker().Add(federationDomainWithoutSecret2))
				r.NoError(pinnipedInformerClient.Tracker().Add(federationDomainWithBadSecret))
				r.NoError(pinnipedInformerClient.Tracker().Add(federationDomainWithBadIssuer))
				r.NoError(pinnipedInformerClient.Tracker().Add(federationDomainWithGoodSecret1))
				r.NoError(pinnipedInformerClient.Tracker().Add(federationDomainWithGoodSecret2))
				r.NoError(kubeInformerClient.Tracker().Add(goodTLSSecret1))
				r.NoError(kubeInformerClient.Tracker().Add(goodTLSSecret2))
				r.NoError(kubeInformerClient.Tracker().Add(badTLSSecret))
			})

			it("updates the issuerTLSCertSetter's map to include only the issuers that had valid certs", func() {
				startInformersAndController()
				r.NoError(controllerlib.TestSync(t, subject, *syncContext))

				r.True(issuerTLSCertSetter.setDefaultTLSCertWasCalled)
				r.Nil(issuerTLSCertSetter.setDefaultTLSCertReceived)

				r.True(issuerTLSCertSetter.setIssuerHostToTLSCertMapWasCalled)
				r.Len(issuerTLSCertSetter.issuerHostToTLSCertMapReceived, 2)

				// They keys in the map should be lower case and should not include the port numbers, because
				// TLS SNI says that SNI hostnames must be DNS names (not ports) and must be case insensitive.
				// See https://tools.ietf.org/html/rfc3546#section-3.1
				actualCertificate1 := issuerTLSCertSetter.issuerHostToTLSCertMapReceived["www.issuer-with-good-secret1.com"]
				r.NotNil(actualCertificate1)
				// The actual cert should match the one from the test fixture that was put into the secret.
				r.Equal(expectedCertificate1, *actualCertificate1)
				actualCertificate2 := issuerTLSCertSetter.issuerHostToTLSCertMapReceived["www.issuer-with-good-secret2.com"]
				r.NotNil(actualCertificate2)
				r.Equal(expectedCertificate2, *actualCertificate2)
			})

			when("there is also a default TLS cert secret with the configured default TLS cert secret name", func() {
				var (
					expectedDefaultCertificate tls.Certificate
				)

				it.Before(func() {
					var err error
					testCrt := readTestFile("testdata/test3.crt")
					r.NotEmpty(testCrt)
					testKey := readTestFile("testdata/test3.key")
					r.NotEmpty(testKey)
					expectedDefaultCertificate, err = tls.X509KeyPair(testCrt, testKey)
					r.NoError(err)
					defaultTLSCertSecret := &corev1.Secret{
						ObjectMeta: metav1.ObjectMeta{Name: defaultTLSSecretName, Namespace: installedInNamespace},
						Data:       map[string][]byte{"tls.crt": testCrt, "tls.key": testKey},
					}
					r.NoError(kubeInformerClient.Tracker().Add(defaultTLSCertSecret))
				})

				it("updates the issuerTLSCertSetter's map as before but also updates the default certificate", func() {
					startInformersAndController()
					r.NoError(controllerlib.TestSync(t, subject, *syncContext))

					r.True(issuerTLSCertSetter.setDefaultTLSCertWasCalled)
					actualDefaultCertificate := issuerTLSCertSetter.setDefaultTLSCertReceived
					r.NotNil(actualDefaultCertificate)
					r.Equal(expectedDefaultCertificate, *actualDefaultCertificate)

					r.True(issuerTLSCertSetter.setIssuerHostToTLSCertMapWasCalled)
					r.Len(issuerTLSCertSetter.issuerHostToTLSCertMapReceived, 2)
				})
			})
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}
