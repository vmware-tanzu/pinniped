// This go.mod file is generated by ./hack/codegen.sh.
module go.pinniped.dev/generated/1.25/client

go 1.13

require (
	go.pinniped.dev/generated/1.25/apis v0.0.0
	k8s.io/apimachinery v0.25.14
	k8s.io/client-go v0.25.14
	k8s.io/kube-openapi v0.0.0-20220803162953-67bda5d908f1
)

replace go.pinniped.dev/generated/1.25/apis => ../apis
