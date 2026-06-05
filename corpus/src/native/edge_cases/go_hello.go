package main

import "fmt"

func compute(n int) int {
	acc := 0
	for i := 1; i <= n; i++ {
		acc += i * i
	}
	return acc
}

func main() {
	fmt.Println(compute(10))
}
