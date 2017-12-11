package auth

import (
	"testing"
)

func TestGetHash(t *testing.T) {
	/*for i := 0; i < 13; i++ {
		code, hash, err := generateStringAndHash()
		if err != nil {
			i--
			continue
		}
		t.Logf(", '%s'), -- code: %s\n", hash, code)
	}*/
}

func TestHash(t *testing.T) {
	store := &hashStore{}
	hash, _ := store.Hash("correctPassword")
	if hash != "zVNfmBbTwQZwyMsAizV1Guh_j7kcFbyG7-LRJeeJfXc=" {
		t.Error("expected match")
	}
	if err := store.HashEquals("correctPassword", hash); err != nil {
		t.Error("expected hash to match back to original", err)
	}
}

func TestCryptoHash(t *testing.T) {
	hash := "$6$rounds=50000$wBYJoagrGVp3mDVC$j3JiX5bOUETQF7LFhU8YZRYmOIbt.9bdL0Uh6q5JYmn4CTpqhpTY2QnnDkAzT2FlnZPQdQ8ZZ.2eqas.ECzCP/"
	password := "MyLamePassword"
	s := &CryptoHashStore{}
	crypt, err := s.Hash(password)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.HashEquals(password, crypt); err != nil {
		t.Fatal("should be able to hash and verify self:", err)
	}
	if err := s.HashEquals(password, hash); err != nil {
		t.Fatal("should match known hash:", err)
	}
}
