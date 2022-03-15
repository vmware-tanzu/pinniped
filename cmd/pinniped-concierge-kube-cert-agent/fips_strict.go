//go:build fips_strict
// +build fips_strict

package main

import (
	_ "crypto/tls/fipsonly" // restricts all TLS configuration to FIPS-approved settings.
	"log"
	"time"
)

func init() {
	go func() {
		time.Sleep(5 * time.Second)
		log.Println("using boringcrypto in fipsonly mode")
	}()
}
