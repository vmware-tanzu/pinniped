// This go.mod file is generated by ./hack/update.sh.
module go.pinniped.dev/generated/1.24/client

go 1.13

replace go.pinniped.dev/generated/1.24/apis => ../apis

require (
	go.pinniped.dev/generated/1.24/apis v0.0.0
	k8s.io/apimachinery v0.24.17
	k8s.io/client-go v0.24.17
	k8s.io/kube-openapi v0.0.0-20220328201542-3ee0da9b0b42
)
