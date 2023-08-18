package main

import "testing"

func TestKZG(t *testing.T) {
	data := genRandom(1*MaxFileSize - 1)

	pk, err := GenKey()
	if err != nil {
		t.Fatal(err)
	}

	com, err := pk.Commitment(data)
	if err != nil {
		t.Fatal(err)
	}

	var rnd Fr
	rnd.SetRandom()

	pf, err := pk.Open(rnd, data)
	if err != nil {
		t.Fatal(err)
	}

	err = pk.Verify(rnd, com, pf)
	if err != nil {
		t.Fatal(err)
	}
}
