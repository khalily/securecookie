package securecookie

import (
	"strings"
	"testing"
)

var (
	secureCookie *SecureCookie
)

func init() {
	secureCookie = &SecureCookie{"123456789", 31}
}

func TestCookieV1(t *testing.T) {
	cookieV1, err := secureCookie.EncodeSecureCookie("c1", "hello world", 1)
	if err != nil {
		t.Error(err)
	}
	t.Log("CookieV1:", cookieV1)

	fields := strings.SplitN(cookieV1, "=", 2)
	result, err := secureCookie.DecodeSecureCookie(fields[0], fields[1])
	if err != nil {
		t.Error(err)
	}
	if result != "hello world" {
		t.Error("diffrent result for cookieV1")
	}
}

func TestCookieV2(t *testing.T) {
	cookieV2, err := secureCookie.EncodeSecureCookie("c2", "hello world too", 2)
	if err != nil {
		t.Error(err)
	}
	t.Log("CookieV2:", cookieV2)

	fields := strings.SplitN(cookieV2, "=", 2)
	result, err := secureCookie.DecodeSecureCookie(fields[0], fields[1])
	if err != nil {
		t.Error(err)
	}
	if result != "hello world too" {
		t.Error("diffrent result for cookieV1")
	}
}
