/*
Copyright 2020 the Pinniped contributors. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package here

import (
	"testing"

	"github.com/sclevine/spec"
	"github.com/sclevine/spec/report"
	"github.com/stretchr/testify/require"
)

func TestDoc(t *testing.T) {
	spec.Run(t, "here.Doc", func(t *testing.T, when spec.G, it spec.S) {
		var r *require.Assertions

		it.Before(func() {
			r = require.New(t)
		})

		it("returns single-line strings unchanged", func() {
			r.Equal("the quick brown fox", Doc("the quick brown fox"))
			r.Equal("  the quick brown fox", Doc("  the quick brown fox"))
		})

		it("returns multi-line strings with indentation removed", func() {
			r.Equal(
				"the quick brown fox\njumped over the\nlazy dog",
				Doc(`the quick brown fox
						jumped over the
						lazy dog`),
			)
		})

		it("ignores the first empty line and the whitespace in the last line", func() {
			r.Equal(
				"the quick brown fox\njumped over the\nlazy dog\n",
				Doc(`
						the quick brown fox
						jumped over the
						lazy dog
				`),
			)
		})

		it("turns all tabs into 4 spaces", func() {
			r.Equal(
				"the quick brown fox\n    jumped over the\n        lazy dog\n",
				Doc(`
						the quick brown fox
							jumped over the
								lazy dog
				`),
			)
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))

	spec.Run(t, "here.Docf", func(t *testing.T, when spec.G, it spec.S) {
		var r *require.Assertions

		it.Before(func() {
			r = require.New(t)
		})

		it("returns single-line strings unchanged", func() {
			r.Equal("the quick brown fox", Docf("the quick brown %s", "fox"))
			r.Equal("  the quick brown fox", Docf("  the %s brown %s", "quick", "fox"))
		})

		it("returns multi-line strings with indentation removed", func() {
			r.Equal(
				"the quick brown fox\njumped over the\nlazy dog",
				Docf(`the quick brown %s
						jumped over the
						lazy %s`, "fox", "dog"),
			)
		})

		it("ignores the first empty line and the whitespace in the last line", func() {
			r.Equal(
				"the quick brown fox\njumped over the\nlazy dog\n",
				Docf(`
						the quick brown %s
						jumped over the
						lazy %s
				`, "fox", "dog"),
			)
		})

		it("turns all tabs into 4 spaces", func() {
			r.Equal(
				"the quick brown fox\n    jumped over the\n        lazy dog\n",
				Docf(`
						the quick brown %s
							jumped over the
								lazy %s
				`, "fox", "dog"),
			)
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}
