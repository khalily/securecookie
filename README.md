# securecookie

    import "github.com/kahlily/securecookie"

securecookie provide a go implementation of tornado (>=3.2) secure cookies.

[![GoDoc](https://godoc.org/github.com/kahlily/securecookie?status.png)](http://godoc.org/github.com/khalily/securecookie) [![Build Status](https://travis-ci.org/khalily/securecookie.png?branch=master)](https://travis-ci.org/khalily/securecookie)


## Usage

#### func EncodeSecureCookie

```go
func EncodeSecureCookie(name, value string, version int) (string, error)
```

Encode a specific version's(1 or 2) secure cookie.

#### func DecodeSecureCookie

```go
func (sc *SecureCookie) DecodeSecureCookie(name, value string) (string, error)
```

Decode a secure cookie generate by EncodeSecureCookie.
