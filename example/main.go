package main

import (
	"fmt"
	"github.com/zilehuda/emailinspector"
)

func main() {
	res := emailinspector.IsEmailValid("nsl79615@nezddddddid.com")
	fmt.Println(res.IsValid, res.Message)
}
