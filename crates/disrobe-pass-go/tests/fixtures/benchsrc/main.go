package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
)

type Number interface {
	~int | ~int64 | ~float64
}

type Stringer interface {
	String() string
}

type Box[T any] struct {
	Value T
	Tag   string
}

type Pair[K comparable, V any] struct {
	Key K
	Val V
}

type Registry[K comparable, V any] struct {
	mu    sync.Mutex
	items map[K]V
}

func (r *Registry[K, V]) Put(k K, v V) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.items == nil {
		r.items = make(map[K]V)
	}
	r.items[k] = v
}

func (r *Registry[K, V]) Get(k K) (V, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.items[k]
	return v, ok
}

func (b Box[T]) Describe() string {
	return b.Tag
}

func (b Box[T]) String() string {
	return fmt.Sprintf("Box(%s)", b.Tag)
}

func Sum[T Number](xs []T) T {
	var total T
	for _, x := range xs {
		total += x
	}
	return total
}

func Map[T, U any](xs []T, f func(T) U) []U {
	out := make([]U, 0, len(xs))
	for _, x := range xs {
		out = append(out, f(x))
	}
	return out
}

func Filter[T any](xs []T, pred func(T) bool) []T {
	out := make([]T, 0, len(xs))
	for _, x := range xs {
		if pred(x) {
			out = append(out, x)
		}
	}
	return out
}

func Keys[K comparable, V any](m map[K]V) []K {
	out := make([]K, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func WrapInt(v int) Box[int] {
	return Box[int]{Value: v, Tag: "int"}
}

func WrapString(v string) Box[string] {
	return Box[string]{Value: v, Tag: "string"}
}

type Tree[T any] struct {
	Val   T
	Left  *Tree[T]
	Right *Tree[T]
}

func (t *Tree[T]) Insert(v T, less func(a, b T) bool) *Tree[T] {
	if t == nil {
		return &Tree[T]{Val: v}
	}
	if less(v, t.Val) {
		t.Left = t.Left.Insert(v, less)
	} else {
		t.Right = t.Right.Insert(v, less)
	}
	return t
}

func (t *Tree[T]) InOrder(visit func(T)) {
	if t == nil {
		return
	}
	t.Left.InOrder(visit)
	visit(t.Val)
	t.Right.InOrder(visit)
}

func process(items []string) string {
	upper := Map(items, strings.ToUpper)
	sort.Strings(upper)
	long := Filter(upper, func(s string) bool { return len(s) > 2 })
	return strings.Join(long, ",")
}

func main() {
	ints := []int{4, 1, 3, 2}
	floats := []float64{1.5, 2.5, 3.0}
	bi := WrapInt(Sum(ints))
	bs := WrapString("xyz")
	p := Pair[string, int]{Key: "k", Val: 42}
	reg := &Registry[string, int]{}
	reg.Put("a", 1)
	reg.Put("b", 2)
	keys := Keys(reg.items)
	sort.Strings(keys)
	var root *Tree[int]
	for _, v := range ints {
		root = root.Insert(v, func(a, b int) bool { return a < b })
	}
	var seq []int
	root.InOrder(func(v int) { seq = append(seq, v) })
	var stringers []Stringer = []Stringer{bi, bs}
	out := process([]string{"go", "rust", "c", "python"})
	fmt.Fprintln(os.Stdout, bi.Describe(), bs.Describe(), p.Key, keys, seq, Sum(floats), out, stringers)
}
