package main

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/kzg"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/hash/mimc"
)

const InputSize = 10

var curveID = ecc.BW6_761
var hashID = hash.MIMC_BW6_761

type Circuit struct {
	Value [InputSize]frontend.Variable
	G1    [InputSize - 1]sw_bls12377.G1Affine // omit first one is G1 one
	Sum   sw_bls12377.G1Affine                `gnark:",public"`
	Hash  frontend.Variable                   `gnark:",public"`
	One   sw_bls12377.G1Affine                `gnark:",public"`
}

func (circuit *Circuit) Define(api frontend.API) error {
	mimc, _ := mimc.NewMiMC(api)
	mimc.Write(circuit.Value[0])
	circuit.One.ScalarMul(api, circuit.One, circuit.Value[0])

	for i := 1; i < InputSize; i++ {
		mimc.Write(circuit.Value[i])
		circuit.G1[i-1].ScalarMul(api, circuit.G1[i-1], circuit.Value[i])
		circuit.One.AddAssign(api, circuit.G1[i-1])
	}
	circuit.Sum.AssertIsEqual(api, circuit.One)
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
		if i == 0 {
			assignment.One.Assign(&kzgSRS.Pk.G1[0])
		} else {
			assignment.G1[i-1].Assign(&kzgSRS.Pk.G1[i])
		}

		tmp.ScalarMultiplication(&kzgSRS.Pk.G1[i], bigval)
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
