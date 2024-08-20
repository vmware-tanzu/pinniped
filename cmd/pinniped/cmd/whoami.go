// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/tools/clientcmd"

	identityv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/identity/v1alpha1"
	conciergescheme "go.pinniped.dev/internal/concierge/scheme"
	"go.pinniped.dev/internal/groupsuffix"
	"go.pinniped.dev/internal/here"
)

type whoamiDeps struct {
	getenv       func(key string) string
	getClientset getConciergeClientsetFunc
}

func whoamiRealDeps() whoamiDeps {
	return whoamiDeps{
		getenv:       os.Getenv,
		getClientset: getRealConciergeClientset,
	}
}

//nolint:gochecknoinits
func init() {
	rootCmd.AddCommand(newWhoamiCommand(whoamiRealDeps()))
}

type whoamiFlags struct {
	outputFormat string // e.g., yaml, json, text
	timeout      time.Duration

	kubeconfigPath            string
	kubeconfigContextOverride string

	apiGroupSuffix string
}

type clusterInfo struct {
	name string
	url  string
}

func newWhoamiCommand(deps whoamiDeps) *cobra.Command {
	cmd := &cobra.Command{
		Args:         cobra.NoArgs, // do not accept positional arguments for this command
		Use:          "whoami",
		Short:        "Print information about the current user",
		SilenceUsage: true, // do not print usage message when commands fail
	}
	flags := &whoamiFlags{}

	// flags
	f := cmd.Flags()
	f.StringVarP(&flags.outputFormat, "output", "o", "text", "Output format (e.g., 'yaml', 'json', 'text')")
	f.StringVar(&flags.kubeconfigPath, "kubeconfig", deps.getenv("KUBECONFIG"), "Path to kubeconfig file")
	f.StringVar(&flags.kubeconfigContextOverride, "kubeconfig-context", "", "Kubeconfig context name (default: current active context)")
	f.StringVar(&flags.apiGroupSuffix, "api-group-suffix", groupsuffix.PinnipedDefaultSuffix, "Concierge API group suffix")
	f.DurationVar(&flags.timeout, "timeout", 0, "Timeout for the WhoAmI API request (default: 0, meaning no timeout)")

	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		return runWhoami(cmd.OutOrStdout(), deps, flags)
	}

	return cmd
}

func runWhoami(output io.Writer, deps whoamiDeps, flags *whoamiFlags) error {
	clientConfig := newClientConfig(flags.kubeconfigPath, flags.kubeconfigContextOverride)
	clientset, err := deps.getClientset(clientConfig, flags.apiGroupSuffix)
	if err != nil {
		return fmt.Errorf("could not configure Kubernetes client: %w", err)
	}

	clusterInfo, err := getCurrentCluster(clientConfig, flags.kubeconfigContextOverride)
	if err != nil {
		return fmt.Errorf("could not get current cluster info: %w", err)
	}

	// Making the WhoAmI request may cause client-go to invoke the credential plugin, which may
	// ask the user to interactively authenticate. The time that the user takes to authenticate
	// is included in the timeout time, but their authentication is not cancelled by exceeding
	// this timeout. Only the subsequent whoami API request is cancelled. Using a short timeout
	// causes the odd behavior of a successful login immediately followed by a whoami request failure
	// due to timeout. For comparison, kubectl uses an infinite timeout by default on API requests
	// but also allows the user to adjust this timeout with the `--request-timeout` CLI option,
	// so we will take a similar approach. Note that kubectl has the same behavior when a client-go
	// credential plugin is invoked and the user takes longer then the timeout to authenticate.
	ctx := context.Background()
	if flags.timeout > 0 {
		var cancelFunc context.CancelFunc
		ctx, cancelFunc = context.WithTimeout(ctx, flags.timeout)
		defer cancelFunc()
	}

	whoAmI, err := clientset.IdentityV1alpha1().WhoAmIRequests().Create(ctx, &identityv1alpha1.WhoAmIRequest{}, metav1.CreateOptions{})
	if err != nil {
		hint := ""
		if apierrors.IsNotFound(err) {
			hint = " (is the Pinniped WhoAmI API running and healthy?)"
		}
		return fmt.Errorf("could not complete WhoAmIRequest%s: %w", hint, err)
	}

	if err := writeWhoamiOutput(output, flags, clusterInfo, whoAmI); err != nil {
		return fmt.Errorf("could not write output: %w", err)
	}

	return nil
}

func getCurrentCluster(clientConfig clientcmd.ClientConfig, currentContextNameOverride string) (*clusterInfo, error) {
	currentKubeConfig, err := clientConfig.RawConfig()
	if err != nil {
		return nil, err
	}

	contextName := currentKubeConfig.CurrentContext
	if len(currentContextNameOverride) > 0 {
		contextName = currentContextNameOverride
	}

	unknownClusterInfo := &clusterInfo{name: "???", url: "???"}
	ctx, ok := currentKubeConfig.Contexts[contextName]
	if !ok {
		return unknownClusterInfo, nil
	}

	cluster, ok := currentKubeConfig.Clusters[ctx.Cluster]
	if !ok {
		return unknownClusterInfo, nil
	}

	return &clusterInfo{name: ctx.Cluster, url: cluster.Server}, nil
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
	scheme, _, identityGV := conciergescheme.New(apiGroupSuffix)
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
