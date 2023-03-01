package main

// Copyright 2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/mod/modfile"
)

func main() {
	goModFilepath := filepath.Clean(os.Args[1])

	if _, err := os.Stat(goModFilepath); err != nil {
		log.Fatalf("File '%s' does not exist\n", goModFilepath)
	}

	var (
		bytes []byte
		err   error
	)
	if bytes, err = os.ReadFile(goModFilepath); err != nil {
		log.Fatalf("Unable to read file '%s'\n", goModFilepath)
	}

	file, err := modfile.Parse(goModFilepath, bytes, nil)
	if err != nil {
		log.Fatalf("Unable to parse file '%s'\n", goModFilepath)
	}

	for _, require := range file.Require {
		if !require.Indirect {
			fmt.Printf("go get %s &&\n", require.Mod.Path)
		}
	}

	fmt.Printf("./hack/module.sh tidy\n")
}
