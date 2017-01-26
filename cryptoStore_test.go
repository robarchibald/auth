package main

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
