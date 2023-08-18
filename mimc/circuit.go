package main

import (
	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/sw_bls12377"
	"github.com/consensys/gnark/std/hash/mimc"
)

var curveID = ecc.BW6_761
var hashID = hash.MIMC_BW6_761

type Circuit struct {
	PreImage sw_bls12377.G1Affine
	Hash     frontend.Variable `gnark:",public"`
}

func (circuit *Circuit) Define(api frontend.API) error {
	mimc, _ := mimc.NewMiMC(api)
	mimc.Write(circuit.PreImage.X)
	mimc.Write(circuit.PreImage.Y)
	api.AssertIsEqual(circuit.Hash, mimc.Sum())
	return nil
}

func GenWithness() (witness.Witness, error) {
	pre, err := bls12377.HashToG1([]byte("test"), []byte("test"))
	if err != nil {
		return nil, err
	}

	h := hashID.New()
	preImageX := pre.X.Bytes()
	preImageY := pre.Y.Bytes()
	h.Write(preImageX[:])
	h.Write(preImageY[:])

	res := h.Sum(nil)

	var assignment Circuit
	assignment.PreImage.Assign(&pre)
	assignment.Hash = res

	witness, err := frontend.NewWitness(&assignment, curveID.ScalarField())
	if err != nil {
		return nil, err
	}

	return witness, nil
}
