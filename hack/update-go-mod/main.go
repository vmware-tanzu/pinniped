// Copyright 2023-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/modfile"
)

func main() {
	goModFilepath := filepath.Clean(os.Args[1])
	overridesFilepath := filepath.Clean(os.Args[2])

	if _, err := os.Stat(goModFilepath); err != nil {
		log.Fatalf("File '%s' does not exist\n", goModFilepath)
	}

	if _, err := os.Stat(overridesFilepath); err != nil {
		log.Fatalf("File '%s' does not exist\n", overridesFilepath)
	}

	var (
		bytes     []byte
		overrides map[string]string
		err       error
	)

	if bytes, err = os.ReadFile(overridesFilepath); err != nil {
		log.Fatalf("Unable to read file '%s'\n", overridesFilepath)
	}

	if overrides, err = parseOverrides(string(bytes)); err != nil {
		log.Fatalf("Parse error in file '%s': %s\n", overridesFilepath, err.Error())
	}

	if bytes, err = os.ReadFile(goModFilepath); err != nil {
		log.Fatalf("Unable to read file '%s'\n", goModFilepath)
	}

	file, err := modfile.Parse(goModFilepath, bytes, nil)
	if err != nil {
		log.Fatalf("Unable to parse file '%s'\n", goModFilepath)
	}

	for _, require := range file.Require {
		if !require.Indirect {
			mod := require.Mod.Path
			overrideMod, hasOverride := overrides[mod]
			if hasOverride {
				if overrideMod == "NEVER_UPGRADE_DIRECTLY" {
					// Do not manually update this direct dependency. Treat it like an indirect dep.
					// Let "go mod tidy" update it to be the minimum version required by our other direct deps.
					continue
				}
				mod = overrideMod
			}
			fmt.Printf("go get %s &&\n", mod)
		}
	}

	fmt.Printf("./hack/module.sh tidy\n")
}

func parseOverrides(overridesText string) (map[string]string, error) {
	overridesMap := map[string]string{}

	lines := strings.Split(overridesText, "\n")

	for i, line := range lines {
		trimmedLine := strings.TrimSpace(line)

		if strings.HasPrefix(trimmedLine, "#") || len(trimmedLine) == 0 {
			continue
		}

		splitLine := strings.Split(trimmedLine, " ")

		if len(splitLine) != 2 {
			return nil, fmt.Errorf(
				"error on line %d: found %d tokens instead of 2 tokens",
				i+1, len(splitLine),
			)
		}

		overridesMap[splitLine[0]] = splitLine[1]
	}

	return overridesMap, nil
}
