package main

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/sw_bls12377"
	"github.com/consensys/gnark/std/commitments/kzg_bls12377"
)

var curveID = ecc.BW6_761

type Circuit struct {
	Commitment sw_bls12377.G1Affine
	Proof      kzg_bls12377.OpeningProof
	Random     frontend.Variable `gnark:",public"`
	VerifyKey  kzg_bls12377.VK   `gnark:",public"`
}

func (circuit *Circuit) Define(api frontend.API) error {
	kzg_bls12377.Verify(api, circuit.Commitment, circuit.Proof, circuit.Random, circuit.VerifyKey)
	return nil
}

func GenWithness() (witness.Witness, error) {
	pk, err := GenKey()
	if err != nil {
		return nil, err
	}

	data := genRandom(1 * MaxFileSize)
	com, err := pk.Commitment(data)
	if err != nil {
		return nil, err
	}

	var rnd Fr
	rnd.SetRandom()

	pf, err := pk.Open(rnd, data)
	if err != nil {
		return nil, err
	}

	err = pk.Verify(rnd, com, pf)
	if err != nil {
		return nil, err
	}

	rndBig := new(big.Int)
	rnd.BigInt(rndBig)
	claimBig := new(big.Int)
	pf.ClaimedValue.BigInt(claimBig)

	var assignment Circuit
	assignment.VerifyKey.G1.Assign(&pk.SRS.G1[0])
	assignment.VerifyKey.G2[0].Assign(&pk.SRS.G2[0])
	assignment.VerifyKey.G2[1].Assign(&pk.SRS.G2[1])
	assignment.Commitment.Assign(&com)
	assignment.Proof.ClaimedValue = claimBig
	assignment.Proof.H.Assign(&pf.H)
	assignment.Random = rndBig

	witness, err := frontend.NewWitness(&assignment, curveID.ScalarField())
	if err != nil {
		return nil, err
	}

	return witness, nil
}
