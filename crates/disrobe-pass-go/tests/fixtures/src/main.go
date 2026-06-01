package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

const greeting string = "hello from disrobe-pass-go fixture"

type buildInfo struct {
	Compiler string
	Goos     string
	Goarch   string
	Version  string
}

func describe() buildInfo {
	return buildInfo{
		Compiler: runtime.Compiler,
		Goos:     runtime.GOOS,
		Goarch:   runtime.GOARCH,
		Version:  runtime.Version(),
	}
}

func main() {
	info := describe()
	parts := []string{
		greeting,
		"compiler=" + info.Compiler,
		"goos=" + info.Goos,
		"goarch=" + info.Goarch,
		"version=" + info.Version,
	}
	if _, err := fmt.Fprintln(os.Stdout, strings.Join(parts, " | ")); err != nil {
		os.Exit(1)
	}
}
