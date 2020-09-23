package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/pkg/errors"
	"github.com/tredoe/osutil/user/crypt/sha512_crypt"
)

var errHashNotEqual = errors.New("input string does not match the supplied hash")

// Crypter interface is used to store the password hash and to compare two password hashes together for equality
type Crypter interface {
	HashEquals(token, tokenHash string) error
	Hash(token string) (string, error)
}

// CryptoHashStore encrypts using an iterated hash with configurable number of iterations
type CryptoHashStore struct {
	Crypter
}

// HashEquals does a constant-time compare to determine if a token is equal to the provided hash
func (c *CryptoHashStore) HashEquals(token, tokenHash string) error {
	hashed, err := cryptoHashWSalt(token, tokenHash) // sha512_crypt will strip out salt from hash
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(hashed), []byte(tokenHash)) != 1 {
		return errHashNotEqual
	}
	return nil
}

// Hash returns a hashed string that has been hashed 50000 times
func (c *CryptoHashStore) Hash(token string) (string, error) {
	salt, err := getRandomSalt(16, 50000)
	if err != nil {
		return "", err
	}
	return cryptoHashWSalt(token, salt)
}

type hashStore struct {
	Crypter
}

func (h *hashStore) HashEquals(token, tokenHash string) error {
	hash, err := base64.URLEncoding.DecodeString(tokenHash)
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
	data, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return "", err
	}
	return encodeToString(hash(data)), nil
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
	tokenBytes, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return err
	}
	hashBytes, err := base64.URLEncoding.DecodeString(tokenHash)
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
	return sha512_crypt.New().Generate([]byte(in), []byte(salt))
}
