package apiserver

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/apiserver/pkg/registry/rest"
	genericapiserver "k8s.io/apiserver/pkg/server"
	restclient "k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	placeholderv1alpha1 "github.com/suzerain-io/placeholder-name-api/pkg/apis/placeholder/v1alpha1"
	"github.com/suzerain-io/placeholder-name/pkg/registry/loginrequest"
)

var (
	scheme = runtime.NewScheme()
	Codecs = serializer.NewCodecFactory(scheme)
)

func init() {
	utilruntime.Must(placeholderv1alpha1.AddToScheme(scheme))

	// we need to add the options to empty v1
	// TODO fix the server code to avoid this
	metav1.AddToGroupVersion(scheme, schema.GroupVersion{Version: "v1"})

	// TODO: keep the generic API server from wanting this
	unversioned := schema.GroupVersion{Group: "", Version: "v1"}
	scheme.AddUnversionedTypes(unversioned,
		&metav1.Status{},
		&metav1.APIVersions{},
		&metav1.APIGroupList{},
		&metav1.APIGroup{},
		&metav1.APIResourceList{},
	)
}

type Config struct {
	GenericConfig *genericapiserver.RecommendedConfig
	ExtraConfig   ExtraConfig
}

type ExtraConfig struct {
	PlaceHolderConfig string // TODO
}

type PlaceHolderServer struct {
	GenericAPIServer *genericapiserver.GenericAPIServer
}

type completedConfig struct {
	GenericConfig genericapiserver.CompletedConfig
	ExtraConfig   *ExtraConfig
}

type CompletedConfig struct {
	// Embed a private pointer that cannot be instantiated outside of this package.
	*completedConfig
}

// Complete fills in any fields not set that are required to have valid data. It's mutating the receiver.
func (c *Config) Complete() CompletedConfig {
	completedCfg := completedConfig{
		c.GenericConfig.Complete(),
		&c.ExtraConfig,
	}

	// TODO fix version
	completedCfg.GenericConfig.Version = &version.Info{
		Major: "0",
		Minor: "1",
	}

	return CompletedConfig{completedConfig: &completedCfg}
}

// New returns a new instance of AdmissionServer from the given config.
func (c completedConfig) New() (*PlaceHolderServer, error) {
	genericServer, err := c.GenericConfig.New("place-holder-server", genericapiserver.NewEmptyDelegate()) // completion is done in Complete, no need for a second time
	if err != nil {
		return nil, fmt.Errorf("completion error: %w", err)
	}

	s := &PlaceHolderServer{
		GenericAPIServer: genericServer,
	}

	inClusterConfig, err := restclient.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in cluster config error: %w", err)
	}

	// TODO this should be v1, not v1alpha1
	gvr := placeholderv1alpha1.SchemeGroupVersion.WithResource("loginrequests")

	apiGroupInfo := genericapiserver.APIGroupInfo{
		PrioritizedVersions:          []schema.GroupVersion{gvr.GroupVersion()},
		VersionedResourcesStorageMap: map[string]map[string]rest.Storage{},
		// TODO unhardcode this.  It was hardcoded before, but we need to re-evaluate
		OptionsExternalVersion: &schema.GroupVersion{Version: "v1"},
		Scheme:                 scheme,
		ParameterCodec:         metav1.ParameterCodec,
		NegotiatedSerializer:   Codecs,
	}

	loginRequestStorage := loginrequest.NewREST(inClusterConfig)

	v1Storage, ok := apiGroupInfo.VersionedResourcesStorageMap[gvr.Version]
	if !ok {
		v1Storage = map[string]rest.Storage{}
	}
	v1Storage[gvr.Resource] = loginRequestStorage
	apiGroupInfo.VersionedResourcesStorageMap[gvr.Version] = v1Storage

	if err := s.GenericAPIServer.InstallAPIGroup(&apiGroupInfo); err != nil {
		return nil, fmt.Errorf("install API group error: %w", err)
	}

	s.GenericAPIServer.AddPostStartHookOrDie("place-holder-post-start-hook",
		func(context genericapiserver.PostStartHookContext) error {
			klog.InfoS("post start hook", "foo", "bar")
			return nil
		},
	)

	return s, nil
}
