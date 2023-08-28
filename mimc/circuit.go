package main

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/kzg"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/sw_bls12377"
	"github.com/consensys/gnark/std/hash/mimc"
)

const InputSize = 10

var curveID = ecc.BW6_761
var hashID = hash.MIMC_BW6_761

type Circuit struct {
	Value [InputSize]frontend.Variable
	G1    [InputSize]sw_bls12377.G1Affine
	Sum   sw_bls12377.G1Affine `gnark:",public"`
	Hash  frontend.Variable    `gnark:",public"`
}

func (circuit *Circuit) Define(api frontend.API) error {
	mimc, _ := mimc.NewMiMC(api)
	mimc.Write(circuit.Value[0])
	circuit.G1[0].ScalarMul(api, circuit.G1[0], circuit.Value[0])

	for i := 1; i < InputSize; i++ {
		mimc.Write(circuit.Value[i])
		circuit.G1[i].ScalarMul(api, circuit.G1[i], circuit.Value[i])
		circuit.G1[0].AddAssign(api, circuit.G1[i])
	}
	circuit.Sum.AssertIsEqual(api, circuit.G1[0])
	api.AssertIsEqual(circuit.Hash, mimc.Sum())
	return nil
}

func GenWithness() (witness.Witness, error) {
	var assignment Circuit

	alpha := big.NewInt(12345678)
	kzgSRS, err := kzg.NewSRS(InputSize, alpha)
	if err != nil {
		return nil, err
	}

	h := hashID.New()
	mod := curveID.ScalarField()
	fieldSize := len(mod.Bytes())

	var sum, tmp bls12377.G1Affine
	var value fr.Element
	for i := 0; i < InputSize; i++ {
		value.SetRandom()
		bigval := new(big.Int)
		value.BigInt(bigval)

		assignment.Value[i] = bigval
		assignment.G1[i].Assign(&kzgSRS.G1[i])
		tmp.ScalarMultiplication(&kzgSRS.G1[i], bigval)
		sum.Add(&sum, &tmp)

		bval := bigval.Bytes()
		bval = append(make([]byte, fieldSize-len(bval)), bval...)
		h.Write(bval)
	}
	hsum := h.Sum(nil)
	assignment.Sum.Assign(&sum)
	assignment.Hash = hsum

	witness, err := frontend.NewWitness(&assignment, curveID.ScalarField())
	if err != nil {
		return nil, err
	}

	return witness, nil
}
