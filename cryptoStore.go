package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

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
func encodedHashEquals(token, tokenHash string) bool {
	tokenBytes, _ := decodeFromString(token)
	hashBytes, _ := decodeFromString(tokenHash)
	return hashEquals(tokenBytes, hashBytes)
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
