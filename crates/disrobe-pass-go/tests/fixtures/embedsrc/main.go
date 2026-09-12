package main

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
)

//go:embed assets/note.txt
var noteData string

//go:embed assets
var assetsFS embed.FS

func main() {
	fmt.Fprintln(os.Stdout, noteData)
	_ = fs.WalkDir(assetsFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			b, rerr := assetsFS.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			fmt.Fprintf(os.Stdout, "%s=%d\n", path, len(b))
		}
		return nil
	})
}
