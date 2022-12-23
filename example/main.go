package main

import (
	"fmt"
)

func __native_entry__() uintptr

func main() {
	println(fmt.Sprintf("__native_entry__() = %#x", __native_entry__()))
}
