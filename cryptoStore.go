package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/kless/osutil/user/crypt/sha512_crypt"
	"github.com/pkg/errors"
)

var errHashNotEqual = errors.New("input string does not match the supplied hash")

type passwordStorer interface {
	HashEquals(token, tokenHash string) error
	Hash(token string) (string, error)
}

type cryptoHashStore struct {
	passwordStorer
}

func (c *cryptoHashStore) HashEquals(token, tokenHash string) error {
	if len(tokenHash) > 7 && tokenHash[0:7] == "{CRYPT}" {
		tokenHash = tokenHash[7:]
	}
	hashed, err := cryptoHashWSalt(token, tokenHash) // sha512_crypt will strip out salt from hash
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(hashed), []byte(tokenHash)) != 1 {
		return errHashNotEqual
	}
	return nil
}

func (c *cryptoHashStore) Hash(token string) (string, error) {
	salt, err := getRandomSalt(16, 50000)
	if err != nil {
		return "", err
	}
	return cryptoHashWSalt(token, salt)
}

type hashStore struct {
	passwordStorer
}

func (h *hashStore) HashEquals(token, tokenHash string) error {
	hash, err := decodeFromString(tokenHash)
	if err != nil {
		return err
	}
	if !hashEquals([]byte(token), hash) {
		return errors.New("supplied token and tokenHash do not match")
	}
	return nil
}

func (h *hashStore) Hash(token string) (string, error) {
	return encodeToString(hash([]byte(token))), nil
}

func decodeStringToHash(token string) (string, error) {
	data, err := decodeFromString(token)
	if err != nil {
		return "", err
	}
	return encodeToString(hash(data)), nil
}

func decodeFromString(token string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(token)
}

func encodeToString(bytes []byte) string {
	return base64.URLEncoding.EncodeToString(bytes)
}

func generateSelectorTokenAndHash() (string, string, string, error) {
	var selector, token, tokenHash string
	selector, err := generateRandomString()
	if err != nil {
		return "", "", "", newLoggedError("Unable to generate rememberMe selector", err)
	}
	token, tokenHash, err = generateStringAndHash()
	if err != nil {
		return "", "", "", newLoggedError("Unable to generate rememberMe token", err)
	}
	return selector, token, tokenHash, nil
}

func generateStringAndHash() (string, string, error) {
	b, err := generateRandomBytes(32)
	if err != nil {
		return "", "", err
	}
	return encodeToString(b), encodeToString(hash(b)), nil
}

func hash(bytes []byte) []byte {
	h := sha256.Sum256(bytes)
	return h[:]
}

// Url decode both the token and the hash and then compare
func encodedHashEquals(token, tokenHash string) error {
	tokenBytes, err := decodeFromString(token)
	if err != nil {
		return err
	}
	hashBytes, err := decodeFromString(tokenHash)
	if err != nil {
		return err
	}
	if !hashEquals(tokenBytes, hashBytes) {
		return errors.New("token and tokenHash do not match")
	}
	return nil
}

func hashEquals(token, tokenHash []byte) bool {
	return subtle.ConstantTimeCompare(hash(token), tokenHash) == 1
}

func generateRandomString() (string, error) {
	bytes, err := generateRandomBytes(32)
	return encodeToString(bytes), err
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func getRandomSalt(length, iterations int) (string, error) {
	const letterBytes = `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\.`
	b := make([]byte, length)
	maxNum := big.NewInt(64)
	for i := range b {
		c, err := rand.Int(rand.Reader, maxNum)
		if err != nil {
			return "", err
		}
		b[i] = letterBytes[int(c.Int64())]
	}
	return fmt.Sprintf("$6$rounds=%d$%s", iterations, b), nil
}

func cryptoHashWSalt(in, salt string) (string, error) {
	gocrypt := sha512_crypt.New()
	hash, err := gocrypt.Generate([]byte(in), []byte(salt))
	if err != nil {
		return "", err
	}
	return "{CRYPT}" + hash, nil
}
