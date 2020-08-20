module github.com/suzerain-io/placeholder-name/test

go 1.14

require (
	github.com/coreos/go-etcd v2.0.0+incompatible // indirect
	github.com/cpuguy83/go-md2man v1.0.10 // indirect
	github.com/davecgh/go-spew v1.1.1
	github.com/docker/docker v0.7.3-0.20190327010347-be7ac8be2ae0 // indirect
	github.com/evanphx/json-patch v4.2.0+incompatible // indirect
	github.com/gophercloud/gophercloud v0.1.0 // indirect
	github.com/stretchr/testify v1.6.1
	github.com/suzerain-io/placeholder-name v0.0.0-20200819182107-1b9a70d089f4
	github.com/suzerain-io/placeholder-name/kubernetes/1.19/api v0.0.0-00010101000000-000000000000
	github.com/suzerain-io/placeholder-name/kubernetes/1.19/client-go v0.0.0-00010101000000-000000000000
	github.com/suzerain-io/placeholder-name/pkg/client v0.0.0-00010101000000-000000000000
	github.com/ugorji/go/codec v0.0.0-20181204163529-d75b2dcb6bc8 // indirect
	k8s.io/api v0.19.0-rc.0
	k8s.io/apimachinery v0.19.0-rc.0
	k8s.io/client-go v0.19.0-rc.0
	k8s.io/klog v1.0.0 // indirect
	k8s.io/kube-aggregator v0.19.0-rc.0
)

replace (
	github.com/suzerain-io/placeholder-name => ../
	github.com/suzerain-io/placeholder-name/kubernetes/1.19/api => ../kubernetes/1.19/api
	github.com/suzerain-io/placeholder-name/kubernetes/1.19/client-go => ../kubernetes/1.19/client-go
	github.com/suzerain-io/placeholder-name/pkg/client => ../pkg/client
)
