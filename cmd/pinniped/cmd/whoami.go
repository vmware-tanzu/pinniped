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
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/tools/clientcmd"

	identityv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/identity/v1alpha1"
	conciergescheme "go.pinniped.dev/internal/concierge/scheme"
	"go.pinniped.dev/internal/groupsuffix"
	"go.pinniped.dev/internal/here"
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
