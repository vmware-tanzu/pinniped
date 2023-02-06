// This go.mod file is generated by ./hack/codegen.sh.
module go.pinniped.dev/generated/1.17/client

go 1.13

require (
	github.com/go-openapi/spec v0.19.3
	go.pinniped.dev/generated/1.17/apis v0.0.0
	k8s.io/apimachinery v0.20.0
	k8s.io/client-go v0.20.0
	k8s.io/kube-openapi v0.0.0-20201113171705-d219536bb9fd
)

replace go.pinniped.dev/generated/1.17/apis => ../apis
