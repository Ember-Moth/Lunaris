// SPDX-License-Identifier: GPL-3.0-only
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const passwordMemory = 64 * 1024
const passwordIterations = 3

func ValidPassword(password string) bool {
	return len(password) >= 12 && len(password) <= 1024 && utf8.ValidString(password)
}
func ValidUsername(name string) bool {
	if len(name) < 1 || len(name) > 64 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}
func HashPassword(password string) (string, error) {
	if !ValidPassword(password) {
		return "", ErrInvalidInput
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, passwordIterations, passwordMemory, 1, 32)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=1$%s$%s", argon2.Version, passwordMemory, passwordIterations, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}
func VerifyPassword(encoded, password string) bool {
	if len(password) > 1024 || !utf8.ValidString(password) {
		return false
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false
	}
	parameters := strings.Split(parts[3], ",")
	if len(parameters) != 3 {
		return false
	}
	var values [3]uint64
	for i, prefix := range []string{"m=", "t=", "p="} {
		if !strings.HasPrefix(parameters[i], prefix) {
			return false
		}
		v, err := strconv.ParseUint(strings.TrimPrefix(parameters[i], prefix), 10, 32)
		if err != nil {
			return false
		}
		values[i] = v
	}
	if values[0] < 19*1024 || values[0] > 128*1024 || values[1] < 2 || values[1] > 5 || values[2] < 1 || values[2] > 4 {
		return false
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) != 16 {
		return false
	}
	want, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(want) != 32 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, uint32(values[1]), uint32(values[0]), uint8(values[2]), 32)
	return subtle.ConstantTimeCompare(got, want) == 1
}
