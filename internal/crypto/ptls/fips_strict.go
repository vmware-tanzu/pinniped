//go:build fips_strict
// +build fips_strict

package ptls

import (
	_ "crypto/tls/fipsonly" // restricts all TLS configuration to FIPS-approved settings.
	"fmt"
)

func main() {
	fmt.Println("using fips only mode.")
}
