package server

import (
	"fmt"
	"io"
	"net"

	"github.com/spf13/cobra"
	genericapiserver "k8s.io/apiserver/pkg/server"
	genericoptions "k8s.io/apiserver/pkg/server/options"

	placeholderv1alpha1 "github.com/suzerain-io/placeholder-name-api/pkg/apis/placeholder/v1alpha1"
	"github.com/suzerain-io/placeholder-name/pkg/apiserver"
)

// TODO this is ignored for now because we nil out etcd options
const defaultEtcdPathPrefix = "/registry/" + placeholderv1alpha1.GroupName

type PlaceHolderServerOptions struct {
	RecommendedOptions *genericoptions.RecommendedOptions

	PlaceHolderConfig string

	StdOut io.Writer
	StdErr io.Writer
}

func NewPlaceHolderServerOptions(out, errOut io.Writer, placeHolderConfig string) *PlaceHolderServerOptions {
	o := &PlaceHolderServerOptions{
		// TODO we will nil out the etcd storage options.  This requires a later level of k8s.io/apiserver
		RecommendedOptions: genericoptions.NewRecommendedOptions(
			defaultEtcdPathPrefix,
			apiserver.Codecs.LegacyCodec(placeholderv1alpha1.SchemeGroupVersion),
		),

		PlaceHolderConfig: placeHolderConfig,

		StdOut: out,
		StdErr: errOut,
	}
	o.RecommendedOptions.Etcd = nil
	o.RecommendedOptions.Admission = nil

	return o
}

func NewCommandStartPlaceHolderServer(out, errOut io.Writer, stopCh <-chan struct{}) *cobra.Command {
	o := NewPlaceHolderServerOptions(out, errOut, "TODO PLACEHOLDER CONFIG")

	cmd := &cobra.Command{
		Short: "Launch a place holder aggregated API server",
		Long:  "Launch a place holder aggregated API server",
		RunE: func(c *cobra.Command, args []string) error {
			if err := o.Complete(); err != nil {
				return err
			}
			if err := o.Validate(args); err != nil {
				return err
			}
			if err := o.RunPlaceHolderServer(stopCh); err != nil {
				return err
			}
			return nil
		},
		Args: cobra.NoArgs,
	}

	flags := cmd.Flags()
	o.RecommendedOptions.AddFlags(flags)

	return cmd
}

func (o *PlaceHolderServerOptions) Validate(args []string) error {
	return nil
}

func (o *PlaceHolderServerOptions) Complete() error {
	return nil
}

func (o *PlaceHolderServerOptions) Config() (*apiserver.Config, error) {
	// TODO have a "real" external address. Get this from some kind of config input or preferably some environment variable.
	if err := o.RecommendedOptions.SecureServing.MaybeDefaultWithSelfSignedCerts("placeholder-name.placeholder.svc", nil, []net.IP{net.ParseIP("127.0.0.1")}); err != nil {
		return nil, fmt.Errorf("error creating self-signed certificates: %w", err)
	}

	serverConfig := genericapiserver.NewRecommendedConfig(apiserver.Codecs)
	if err := o.RecommendedOptions.ApplyTo(serverConfig); err != nil {
		return nil, err
	}

	config := &apiserver.Config{
		GenericConfig: serverConfig,
		ExtraConfig: apiserver.ExtraConfig{
			PlaceHolderConfig: o.PlaceHolderConfig,
		},
	}
	return config, nil
}

func (o *PlaceHolderServerOptions) RunPlaceHolderServer(stopCh <-chan struct{}) error {
	config, err := o.Config()
	if err != nil {
		return err
	}

	server, err := config.Complete().New()
	if err != nil {
		return err
	}

	return server.GenericAPIServer.PrepareRun().Run(stopCh)
}
