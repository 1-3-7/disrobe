package main

import (
	"fmt"
	"os"
	"strings"
)

var sink int

func NoDefer(n int) int {
	sink += n
	return sink * 3
}

func OpenCodedOne(n int) int {
	defer func() { sink += n }()
	return sink + n
}

func OpenCodedThree(a int, b string) string {
	var sb strings.Builder
	defer func() { sink++ }()
	defer func() { sink += a }()
	defer func() { sb.Reset() }()
	sb.WriteString(b)
	return sb.String()
}

func LoopDefer(n int) int {
	for i := 0; i < n; i++ {
		defer func() { sink += i }()
	}
	return sink
}

func LoopAndPlainDefer(n int) int {
	defer func() { sink -= 1 }()
	for i := 0; i < n; i++ {
		defer func() { sink += i }()
	}
	return sink
}

func ManyReturnsManyDefers(n int) int {
	defer func() { sink++ }()
	defer func() { sink += 2 }()
	defer func() { sink += 3 }()
	defer func() { sink += 4 }()
	if n == 1 {
		return 1
	}
	if n == 2 {
		return 2
	}
	if n == 3 {
		return 3
	}
	if n == 4 {
		return 4
	}
	if n == 5 {
		return 5
	}
	return 0
}

func NineDefers(n int) int {
	defer func() { sink += 1 }()
	defer func() { sink += 2 }()
	defer func() { sink += 3 }()
	defer func() { sink += 4 }()
	defer func() { sink += 5 }()
	defer func() { sink += 6 }()
	defer func() { sink += 7 }()
	defer func() { sink += 8 }()
	defer func() { sink += 9 }()
	return sink + n
}

func WithRecover(n int) (out int) {
	defer func() {
		if r := recover(); r != nil {
			out = -1
		}
	}()
	if n < 0 {
		panic("negative")
	}
	return n * 2
}

func Panics(n int) int {
	if n == 7 {
		panic(fmt.Sprintf("bad %d", n))
	}
	return n
}

func DeferWithFileClose(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var buf [8]byte
	_, err = f.Read(buf[:])
	return err
}

type Res struct{ id int }

func (r *Res) Close() { sink += r.id }

func MethodDefer(r *Res) int {
	defer r.Close()
	return r.id
}

func Nested(n int) int {
	inner := func(k int) int {
		defer func() { sink += k }()
		return k * 2
	}
	return inner(n) + inner(n+1)
}

func main() {
	fmt.Println(NoDefer(1), OpenCodedOne(2), OpenCodedThree(3, "x"))
	fmt.Println(LoopDefer(2), LoopAndPlainDefer(2), ManyReturnsManyDefers(3))
	fmt.Println(NineDefers(1), WithRecover(-1), Panics(1))
	fmt.Println(DeferWithFileClose(os.Args[0]), MethodDefer(&Res{id: 4}), Nested(5))
}
