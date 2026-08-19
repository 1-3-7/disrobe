package main

import (
	"embed"
	"os"
)

//go:embed assets
var assetsFS embed.FS

func main() {
	entries, err := assetsFS.ReadDir("assets")
	if err != nil {
		os.Exit(1)
	}
	os.Exit(len(entries))
}
