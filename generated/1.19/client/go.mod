// This go.mod file is generated by ./hack/codegen.sh.
module go.pinniped.dev/generated/1.19/client

go 1.13

require (
	go.pinniped.dev/generated/1.19/apis v0.0.0-00010101000000-000000000000
	k8s.io/apimachinery v0.19.5
	k8s.io/client-go v0.19.5
)

replace go.pinniped.dev/generated/1.19/apis => ../apis
