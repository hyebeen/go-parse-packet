package goparsepacket

import (
	"fmt"
)

func Test1() {
	fmt.Println("Test")
}

func Test2(s string) {
	fmt.Println("Test", s)
}

func Test3(s string) string {
	return "Test" + s
}
