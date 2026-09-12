package main

import (
	"fmt"
	"io/fs"
	"os"
	"reflect"
)

type Widget struct {
	Name  string
	Count int
}

type Processor interface {
	Process(w Widget) int
}

type counter struct{ total int }

func (c *counter) Process(w Widget) int { c.total += w.Count; return c.total }

func kinds(v any) reflect.Kind { return reflect.TypeOf(v).Kind() }

func main() {
	c := &counter{}
	widgets := []Widget{{Name: "alpha", Count: 3}, {Name: "beta", Count: 5}}
	sum := 0
	var p Processor = c
	for _, w := range widgets {
		sum += p.Process(w)
	}
	var err error = &fs.PathError{Op: "open", Path: "x", Err: os.ErrNotExist}
	fmt.Fprintln(os.Stdout, sum, kinds(widgets), err)
	os.Exit(sum & 0)
}
