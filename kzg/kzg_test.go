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

func TestMultiKZG(t *testing.T) {
	pk, err := GenKey()
	if err != nil {
		t.Fatal(err)
	}

	var rnd Fr
	rnd.SetRandom()

	var accCom G1
	var accProof Proof
	for i := 0; i < 2; i++ {
		data := genRandom(1 * MaxFileSize)

		com, err := pk.Commitment(data)
		if err != nil {
			t.Fatal(err)
		}

		pf, err := pk.Open(rnd, data)
		if err != nil {
			t.Fatal(err)
		}

		err = pk.Verify(rnd, com, pf)
		if err != nil {
			t.Fatal(err)
		}
		accCom.Add(&accCom, &com)
		accProof.ClaimedValue.Add(&accProof.ClaimedValue, &pf.ClaimedValue)
		accProof.H.Add(&accProof.H, &pf.H)
	}

	err = pk.Verify(rnd, accCom, accProof)
	if err != nil {
		t.Fatal(err)
	}
}
