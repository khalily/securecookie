package securecookie

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	DEFAULT_SIGNED_VALUE_MIN_VERSION = 1
)

var (
	signedValueVersionRE *regexp.Regexp
)

func init() {
	signedValueVersionRE = regexp.MustCompile(`([1-9][0-9]*)|(.*)$`)
}

type SecureCookie struct {
	Secret     string
	MaxAgeDays int
}

func (sc *SecureCookie) EncodeSecureCookie(name, value string, version int) (string, error) {
	now := time.Now().Unix()
	signedValue, err := createSignedValue(sc.Secret, name, value, version, now)
	if err != nil {
		return "", err
	}
	cookie := name + "=" + signedValue
	return cookie, nil
}

func (sc *SecureCookie) DecodeSecureCookie(name, value string) (string, error) {
	clock := time.Now().Unix()
	minVersion := DEFAULT_SIGNED_VALUE_MIN_VERSION
	return decodeSignedValue(sc.Secret, name, value, sc.MaxAgeDays, minVersion, clock)
}

func createSignedValue(secret, name, value string, version int, clock int64) (string, error) {
	timestamp := strconv.FormatInt(clock, 10)
	value = base64.StdEncoding.EncodeToString([]byte(value))
	switch version {
	case 1:
		signature, err := createSignatureV1(secret, name, value, timestamp)
		if err != nil {
			return "", err
		}
		return strings.Join([]string{value, timestamp, signature}, "|"), nil
	case 2:
		formatField := func(s string) string {
			return fmt.Sprintf("%d:", len(s)) + s
		}
		// Unsupported keyVersion
		keyVersion := 0
		toSign := strings.Join([]string{
			"2",
			formatField(strconv.Itoa(keyVersion)),
			formatField(timestamp),
			formatField(name),
			formatField(value),
			"",
		}, "|")
		signature, err := createSignatureV2(secret, toSign)
		if err != nil {
			return "", nil
		}
		return toSign + signature, nil
	}
	return "", fmt.Errorf("Unsupported version %d", version)
}

func getVersion(value string) int {
	version := 1
	if signedValueVersionRE.MatchString(value) {
		var err error
		version, err = strconv.Atoi(signedValueVersionRE.FindStringSubmatch(value)[1])
		if err != nil {
			version = 1
		} else if version > 999 {
			version = 1
		}
	}
	return version
}

func decodeSignedValue(secret, name, value string, maxAgeDays, minVersion int, clock int64) (string, error) {
	if minVersion > 2 {
		return "", fmt.Errorf("Unsupported minVersion %d", minVersion)
	}
	version := getVersion(value)
	if version < minVersion {
		return "", fmt.Errorf("version %d less minVersion %d", version, minVersion)
	}

	switch version {
	case 1:
		return decodeSignedValueV1(secret, name, value, maxAgeDays, clock)
	case 2:
		return decodeSignedValueV2(secret, name, value, maxAgeDays, clock)
	}
	return "", fmt.Errorf("Unsupported version %d", version)
}

func decodeSignedValueV1(secret, name, value string, maxAgeDays int, clock int64) (string, error) {
	parts := strings.Split(value, "|")
	if len(parts) != 3 {
		return "", fmt.Errorf("InValid Format: %s", value)
	}
	signature, err := createSignatureV1(secret, name, parts[0], parts[1])
	if err != nil {
		return "", err
	}
	if !timeIndependentEquals(parts[2], signature) {
		return "", fmt.Errorf("InValid cookie signature %s", value)
	}
	if timestamp, err := strconv.ParseInt(parts[1], 10, 64); err != nil {
		return "", fmt.Errorf("InValid Format: %s", value)
	} else {
		if timestamp < clock-int64(maxAgeDays*86400) {
			return "", fmt.Errorf("Expired cookie %s", value)
		}
		if timestamp > clock+31*86400 {
			return "", fmt.Errorf("Cookie timestamp in future; possible tampering %s", value)
		}
	}
	data, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func decodeSignedValueV2(secret, name, value string, maxAgeDays int, clock int64) (string, error) {
	_, timestamp, nameField, valueField, passedSig, err := decodeFieldsV2(value)
	if err != nil {
		return "", err
	}
	signedStr := value[:len(value)-len(passedSig)]

	expectedSig, err := createSignatureV2(secret, signedStr)
	if err != nil {
		return "", err
	}
	if !timeIndependentEquals(passedSig, expectedSig) {
		return "", fmt.Errorf("InValid Cookie Value: %s", value)
	}
	if nameField != name {
		return "", fmt.Errorf("InValid Cookie Value: %s", value)
	}
	if timestamp < clock-int64(maxAgeDays*86400) {
		return "", fmt.Errorf("Expired cookie %s", value)
	}

	data, err := base64.StdEncoding.DecodeString(valueField)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func createSignatureV2(secret, signedStr string) (string, error) {
	mac := hmac.New(sha256.New, []byte(secret))
	if _, err := mac.Write([]byte(signedStr)); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", mac.Sum(nil)), nil
}

func decodeFieldsV2(value string) (keyVersion int, timestamp int64, nameField, valueField, passedSig string, err error) {
	partition := func(s, sep string) (head, tail string) {
		fields := strings.SplitN(s, sep, 2)
		head, tail = fields[0], fields[1]
		return
	}

	consumeField := func(s string) (string, string) {
		length, rest := partition(s, ":")
		n, err := strconv.Atoi(length)
		if err != nil {
			panic(err)
		}
		fieldValue := rest[:n]
		if rest[n:n+1] != "|" {
			panic("malformed v2 signed value field")
		}
		rest = rest[n+1:]
		return fieldValue, rest
	}

	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("%v", e)
		}
	}()

	rest := value[2:] // remove version number
	keyVersionStr, rest := consumeField(rest)
	timestampStr, rest := consumeField(rest)
	nameField, rest = consumeField(rest)
	valueField, passedSig = consumeField(rest)

	keyVersion, err = strconv.Atoi(keyVersionStr)
	timestamp, err = strconv.ParseInt(timestampStr, 10, 64)
	return
}

func timeIndependentEquals(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte

	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

func createSignatureV1(secret string, parts ...string) (string, error) {
	mac := hmac.New(sha1.New, []byte(secret))
	for _, part := range parts {
		if _, err := mac.Write([]byte(part)); err != nil {
			return "", err
		}
	}
	return fmt.Sprintf("%x", mac.Sum(nil)), nil
}
