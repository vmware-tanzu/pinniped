// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/clientcmd"

	identityapi "go.pinniped.dev/generated/latest/apis/concierge/identity"
	identityv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/identity/v1alpha1"
	loginapi "go.pinniped.dev/generated/latest/apis/concierge/login"
	loginv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/login/v1alpha1"
	"go.pinniped.dev/internal/groupsuffix"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/plog"
)

//nolint: gochecknoinits
func init() {
	rootCmd.AddCommand(newWhoamiCommand(getRealConciergeClientset))
}

type whoamiFlags struct {
	outputFormat string // e.g., yaml, json, text

	kubeconfigPath            string
	kubeconfigContextOverride string

	apiGroupSuffix string
}

type clusterInfo struct {
	name string
	url  string
}

func newWhoamiCommand(getClientset getConciergeClientsetFunc) *cobra.Command {
	cmd := &cobra.Command{
		Args:         cobra.NoArgs, // do not accept positional arguments for this command
		Use:          "whoami",
		Short:        "Print information about the current user",
		SilenceUsage: true,
	}
	flags := &whoamiFlags{}

	// flags
	f := cmd.Flags()
	f.StringVarP(&flags.outputFormat, "output", "o", "text", "Output format (e.g., 'yaml', 'json', 'text')")
	f.StringVar(&flags.kubeconfigPath, "kubeconfig", os.Getenv("KUBECONFIG"), "Path to kubeconfig file")
	f.StringVar(&flags.kubeconfigContextOverride, "kubeconfig-context", "", "Kubeconfig context name (default: current active context)")
	f.StringVar(&flags.apiGroupSuffix, "api-group-suffix", groupsuffix.PinnipedDefaultSuffix, "Concierge API group suffix")

	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		return runWhoami(cmd.OutOrStdout(), getClientset, flags)
	}

	return cmd
}

func runWhoami(output io.Writer, getClientset getConciergeClientsetFunc, flags *whoamiFlags) error {
	clientConfig := newClientConfig(flags.kubeconfigPath, flags.kubeconfigContextOverride)
	clientset, err := getClientset(clientConfig, flags.apiGroupSuffix)
	if err != nil {
		return fmt.Errorf("could not configure Kubernetes client: %w", err)
	}

	clusterInfo, err := getCurrentCluster(clientConfig)
	if err != nil {
		return fmt.Errorf("could not get current cluster info: %w", err)
	}

	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second*20)
	defer cancelFunc()
	whoAmI, err := clientset.IdentityV1alpha1().WhoAmIRequests().Create(ctx, &identityv1alpha1.WhoAmIRequest{}, metav1.CreateOptions{})
	if err != nil {
		hint := ""
		if errors.IsNotFound(err) {
			hint = " (is the Pinniped WhoAmI API running and healthy?)"
		}
		return fmt.Errorf("could not complete WhoAmIRequest%s: %w", hint, err)
	}

	if err := writeWhoamiOutput(output, flags, clusterInfo, whoAmI); err != nil {
		return fmt.Errorf("could not write output: %w", err)
	}

	return nil
}

func getCurrentCluster(clientConfig clientcmd.ClientConfig) (*clusterInfo, error) {
	currentKubeconfig, err := clientConfig.RawConfig()
	if err != nil {
		return nil, err
	}

	unknownClusterInfo := &clusterInfo{name: "???", url: "???"}
	context, ok := currentKubeconfig.Contexts[currentKubeconfig.CurrentContext]
	if !ok {
		return unknownClusterInfo, nil
	}

	cluster, ok := currentKubeconfig.Clusters[context.Cluster]
	if !ok {
		return unknownClusterInfo, nil
	}

	return &clusterInfo{name: context.Cluster, url: cluster.Server}, nil
}

func writeWhoamiOutput(output io.Writer, flags *whoamiFlags, cInfo *clusterInfo, whoAmI *identityv1alpha1.WhoAmIRequest) error {
	switch flags.outputFormat {
	case "text":
		return writeWhoamiOutputText(output, cInfo, whoAmI)
	case "json":
		return writeWhoamiOutputJSON(output, flags.apiGroupSuffix, whoAmI)
	case "yaml":
		return writeWhoamiOutputYAML(output, flags.apiGroupSuffix, whoAmI)
	default:
		return fmt.Errorf("unknown output format: %q", flags.outputFormat)
	}
}

func writeWhoamiOutputText(output io.Writer, clusterInfo *clusterInfo, whoAmI *identityv1alpha1.WhoAmIRequest) error {
	fmt.Fprint(output, here.Docf(`
		Current cluster info:

		Name: %s
		URL: %s

		Current user info:

		Username: %s
		Groups: %s
`, clusterInfo.name, clusterInfo.url, whoAmI.Status.KubernetesUserInfo.User.Username, prettyStrings(whoAmI.Status.KubernetesUserInfo.User.Groups)))
	return nil
}

func writeWhoamiOutputJSON(output io.Writer, apiGroupSuffix string, whoAmI *identityv1alpha1.WhoAmIRequest) error {
	return serialize(output, apiGroupSuffix, whoAmI, runtime.ContentTypeJSON)
}

func writeWhoamiOutputYAML(output io.Writer, apiGroupSuffix string, whoAmI *identityv1alpha1.WhoAmIRequest) error {
	return serialize(output, apiGroupSuffix, whoAmI, runtime.ContentTypeYAML)
}

func serialize(output io.Writer, apiGroupSuffix string, whoAmI *identityv1alpha1.WhoAmIRequest, contentType string) error {
	scheme, _, identityGV := conciergeschemeNew(apiGroupSuffix)
	codecs := serializer.NewCodecFactory(scheme)
	respInfo, ok := runtime.SerializerInfoForMediaType(codecs.SupportedMediaTypes(), contentType)
	if !ok {
		return fmt.Errorf("unknown content type: %q", contentType)
	}

	// I have seen the pretty serializer be nil before, so this will hopefully protect against that
	// corner.
	serializer := respInfo.PrettySerializer
	if serializer == nil {
		serializer = respInfo.Serializer
	}

	// Ensure that these fields are set so that the JSON/YAML output tells the full story.
	whoAmI.APIVersion = identityGV.String()
	whoAmI.Kind = "WhoAmIRequest"

	return serializer.Encode(whoAmI, output)
}

func prettyStrings(ss []string) string {
	b := &strings.Builder{}
	for i, s := range ss {
		if i != 0 {
			b.WriteString(", ")
		}
		b.WriteString(s)
	}
	return b.String()
}

// conciergeschemeNew is a temporary private function to stand in place for
// "go.pinniped.dev/internal/concierge/scheme".New until the later function is merged to main.
func conciergeschemeNew(apiGroupSuffix string) (_ *runtime.Scheme, login, identity schema.GroupVersion) {
	// standard set up of the server side scheme
	scheme := runtime.NewScheme()

	// add the options to empty v1
	metav1.AddToGroupVersion(scheme, metav1.Unversioned)

	// nothing fancy is required if using the standard group suffix
	if apiGroupSuffix == groupsuffix.PinnipedDefaultSuffix {
		schemeBuilder := runtime.NewSchemeBuilder(
			loginv1alpha1.AddToScheme,
			loginapi.AddToScheme,
			identityv1alpha1.AddToScheme,
			identityapi.AddToScheme,
		)
		utilruntime.Must(schemeBuilder.AddToScheme(scheme))
		return scheme, loginv1alpha1.SchemeGroupVersion, identityv1alpha1.SchemeGroupVersion
	}

	loginConciergeGroupData, identityConciergeGroupData := groupsuffix.ConciergeAggregatedGroups(apiGroupSuffix)

	addToSchemeAtNewGroup(scheme, loginv1alpha1.GroupName, loginConciergeGroupData.Group, loginv1alpha1.AddToScheme, loginapi.AddToScheme)
	addToSchemeAtNewGroup(scheme, identityv1alpha1.GroupName, identityConciergeGroupData.Group, identityv1alpha1.AddToScheme, identityapi.AddToScheme)

	// manually register conversions and defaulting into the correct scheme since we cannot directly call AddToScheme
	schemeBuilder := runtime.NewSchemeBuilder(
		loginv1alpha1.RegisterConversions,
		loginv1alpha1.RegisterDefaults,
		identityv1alpha1.RegisterConversions,
		identityv1alpha1.RegisterDefaults,
	)
	utilruntime.Must(schemeBuilder.AddToScheme(scheme))

	// we do not want to return errors from the scheme and instead would prefer to defer
	// to the REST storage layer for consistency.  The simplest way to do this is to force
	// a cache miss from the authenticator cache.  Kube API groups are validated via the
	// IsDNS1123Subdomain func thus we can easily create a group that is guaranteed never
	// to be in the authenticator cache.  Add a timestamp just to be extra sure.
	const authenticatorCacheMissPrefix = "_INVALID_API_GROUP_"
	authenticatorCacheMiss := authenticatorCacheMissPrefix + time.Now().UTC().String()

	// we do not have any defaulting functions for *loginv1alpha1.TokenCredentialRequest
	// today, but we may have some in the future.  Calling AddTypeDefaultingFunc overwrites
	// any previously registered defaulting function.  Thus to make sure that we catch
	// a situation where we add a defaulting func, we attempt to call it here with a nil
	// *loginv1alpha1.TokenCredentialRequest.  This will do nothing when there is no
	// defaulting func registered, but it will almost certainly panic if one is added.
	scheme.Default((*loginv1alpha1.TokenCredentialRequest)(nil))

	// on incoming requests, restore the authenticator API group to the standard group
	// note that we are responsible for duplicating this logic for every external API version
	scheme.AddTypeDefaultingFunc(&loginv1alpha1.TokenCredentialRequest{}, func(obj interface{}) {
		credentialRequest := obj.(*loginv1alpha1.TokenCredentialRequest)

		if credentialRequest.Spec.Authenticator.APIGroup == nil {
			// force a cache miss because this is an invalid request
			plog.Debug("invalid token credential request, nil group", "authenticator", credentialRequest.Spec.Authenticator)
			credentialRequest.Spec.Authenticator.APIGroup = &authenticatorCacheMiss
			return
		}

		restoredGroup, ok := groupsuffix.Unreplace(*credentialRequest.Spec.Authenticator.APIGroup, apiGroupSuffix)
		if !ok {
			// force a cache miss because this is an invalid request
			plog.Debug("invalid token credential request, wrong group", "authenticator", credentialRequest.Spec.Authenticator)
			credentialRequest.Spec.Authenticator.APIGroup = &authenticatorCacheMiss
			return
		}

		credentialRequest.Spec.Authenticator.APIGroup = &restoredGroup
	})

	return scheme, schema.GroupVersion(loginConciergeGroupData), schema.GroupVersion(identityConciergeGroupData)
}

func addToSchemeAtNewGroup(scheme *runtime.Scheme, oldGroup, newGroup string, funcs ...func(*runtime.Scheme) error) {
	// we need a temporary place to register our types to avoid double registering them
	tmpScheme := runtime.NewScheme()
	schemeBuilder := runtime.NewSchemeBuilder(funcs...)
	utilruntime.Must(schemeBuilder.AddToScheme(tmpScheme))

	for gvk := range tmpScheme.AllKnownTypes() {
		if gvk.GroupVersion() == metav1.Unversioned {
			continue // metav1.AddToGroupVersion registers types outside of our aggregated API group that we need to ignore
		}

		if gvk.Group != oldGroup {
			panic(fmt.Errorf("tmp scheme has type not in the old aggregated API group %s: %s", oldGroup, gvk)) // programmer error
		}

		obj, err := tmpScheme.New(gvk)
		if err != nil {
			panic(err) // programmer error, scheme internal code is broken
		}
		newGVK := schema.GroupVersionKind{
			Group:   newGroup,
			Version: gvk.Version,
			Kind:    gvk.Kind,
		}

		// register the existing type but with the new group in the correct scheme
		scheme.AddKnownTypeWithName(newGVK, obj)
	}
}
