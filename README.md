# crx-manifest-parser

[![Go Reference](https://pkg.go.dev/badge/github.com/theluckystrike/crx-manifest-parser.svg)](https://pkg.go.dev/github.com/theluckystrike/crx-manifest-parser)

A focused Go library for parsing Chromium extension `manifest.json` files
(Manifest V2 and V3) into a strongly-typed value. It models the fields that
extension tooling most often needs — actions, background workers, content
scripts, permissions, CSP, commands, settings overrides — while tolerating
unknown fields by retaining them in `Raw`.

This package is the parsing core used by the extension analysis tools at
**[zovo.one](https://zovo.one)**.

## Install

```sh
go get github.com/theluckystrike/crx-manifest-parser@latest
```

## Usage

```go
package main

import (
	"fmt"
	"os"

	"github.com/theluckystrike/crx-manifest-parser"
)

func main() {
	data, _ := os.ReadFile("manifest.json")
	m, err := crxmanifestparser.ParseBytes(data)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s v%s (MV%d)\n", m.Name, m.Version, m.ManifestVersion)
	fmt.Println("permissions:", m.AllPermissions())
}
```

## Why

The extension tooling at [zovo.one](https://zovo.one) needs to read, validate,
and audit manifests without dragging in a full schema validator. This module
exposes that tolerant parser as a standalone, dependency-free Go package.

## License

MIT
