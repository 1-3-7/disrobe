package main

import (
	"fmt"
	"os"
)

type Number interface {
	~int | ~int64 | ~float64
}

type Box[T any] struct {
	Value T
	Tag   string
}

type Pair[K comparable, V any] struct {
	Key K
	Val V
}

//go:noinline
func (b Box[T]) Describe() string {
	return b.Tag
}

//go:noinline
func Sum[T Number](xs []T) T {
	var total T
	for _, x := range xs {
		total += x
	}
	return total
}

//go:noinline
func MapKeys[K comparable, V any](m map[K]V) []K {
	out := make([]K, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

//go:noinline
func WrapInt(v int) Box[int] {
	return Box[int]{Value: v, Tag: "int"}
}

//go:noinline
func WrapString(v string) Box[string] {
	return Box[string]{Value: v, Tag: "string"}
}

func main() {
	ints := []int{1, 2, 3, 4}
	floats := []float64{1.5, 2.5, 3.0}
	bi := WrapInt(Sum(ints))
	bs := WrapString("xyz")
	p := Pair[string, int]{Key: "k", Val: 42}
	pm := Pair[int, string]{Key: 7, Val: "v"}
	m := map[string]int{"a": 1, "b": 2}
	keys := MapKeys(m)
	fs := Sum(floats)
	fmt.Fprintln(os.Stdout, bi.Describe(), bs.Describe(), bi.Value, bs.Value, p.Key, pm.Val, keys, fs)
}
