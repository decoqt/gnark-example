package main

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/yydfjt/gnark-example/lib/kzg"
)

var curveID = ecc.BW6_761

type Circuit struct {
	Proof      kzg.OpeningProof
	Commitment sw_bls12377.G1Affine `gnark:",public"`
	Challenge  frontend.Variable    `gnark:",public"`
	VerifyKey  kzg.VK               `gnark:",public"`
}

func (circuit *Circuit) Define(api frontend.API) error {
	kzg.Verify(api, circuit.Commitment, circuit.Proof, circuit.Challenge, circuit.VerifyKey)
	return nil
}

func GenWithness() (witness.Witness, error) {
	pk, err := kzg.GenKey()
	if err != nil {
		return nil, err
	}

	data := kzg.GenRandom(1 * kzg.MaxFileSize)
	com, err := pk.Commitment(data)
	if err != nil {
		return nil, err
	}

	var rnd kzg.Fr
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
	assignment.VerifyKey.G1.Assign(&pk.Vk.G1)
	assignment.VerifyKey.G2[0] = sw_bls12377.NewG2Affine(pk.Vk.G2[0])
	assignment.VerifyKey.G2[1] = sw_bls12377.NewG2Affine(pk.Vk.G2[1])
	assignment.Commitment.Assign(&com)
	assignment.Proof.ClaimedValue = claimBig
	assignment.Proof.H.Assign(&pf.H)
	assignment.Challenge = rndBig

	witness, err := frontend.NewWitness(&assignment, curveID.ScalarField())
	if err != nil {
		return nil, err
	}

	return witness, nil
}
