package main

import (
	"fmt"
	"log"
	"strings"
	"github.com/khalily/securecookie"
)

var (
	secureCookie *securecookie.SecureCookie
)

func init() {
	secureCookie = &securecookie.SecureCookie{"123456789", 31}
}

func TestCookieV1() {
	cookieV1, err := secureCookie.EncodeSecureCookie("c1", "hello world", 1)
	if err != nil {
		log.Fatalln(err)
	}
	log.Println("CookieV1:", cookieV1)

	fields := strings.SplitN(cookieV1, "=", 2)
	fmt.Println(fields)
	result, err := secureCookie.DecodeSecureCookie(fields[0], fields[1])
	if err != nil {
		log.Fatal(err)
	}
	log.Println(result)
}

func TestCookieV2() {
	cookieV2, err := secureCookie.EncodeSecureCookie("c2", "hello world too", 2)
	if err != nil {
		log.Fatalln(err)
	}
	log.Println("CookieV2:", cookieV2)

	fields := strings.SplitN(cookieV2, "=", 2)
	fmt.Println(fields)
	result, err := secureCookie.DecodeSecureCookie(fields[0], fields[1])
	if err != nil {
		log.Fatal(err)
	}
	log.Println(result)
}

func main() {
	TestCookieV1()
	TestCookieV2()
}
