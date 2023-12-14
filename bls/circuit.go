package main

import (
	"strconv"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
)

var curveID = ecc.BW6_761

const inputSize = 1000

type Circuit struct {
	Input [inputSize]sw_bls12377.G1Affine
	Sum   sw_bls12377.G1Affine `gnark:",public"`

	Input2 [inputSize]sw_bls12377.G2Affine `gnark:",public"`
	Sum2   sw_bls12377.G2Affine            `gnark:",public"`
}

func (circuit *Circuit) Define(api frontend.API) error {
	for i := 1; i < inputSize; i++ {
		circuit.Input[0].AddAssign(api, circuit.Input[i])
		circuit.Input2[0].P.AddAssign(api, circuit.Input2[i].P)

	}

	circuit.Sum.AssertIsEqual(api, circuit.Input[0])
	circuit.Sum2.P.AssertIsEqual(api, circuit.Input2[0].P)
	return nil
}

func GenWithness() (witness.Witness, error) {
	var assignment Circuit
	var res bls12377.G1Affine
	var res2 bls12377.G2Affine
	for i := 0; i < inputSize; i++ {
		g1, err := bls12377.HashToG1([]byte(strconv.Itoa(i)), []byte("test"))
		if err != nil {
			return nil, err
		}
		res.Add(&res, &g1)
		assignment.Input[i].Assign(&g1)

		g2, err := bls12377.HashToG2([]byte(strconv.Itoa(i)), []byte("test"))
		if err != nil {
			return nil, err
		}
		res2.Add(&res2, &g2)
		assignment.Input2[i] = sw_bls12377.NewG2Affine(g2)
	}

	assignment.Sum.Assign(&res)
	assignment.Sum2 = sw_bls12377.NewG2Affine(res2)

	witness, err := frontend.NewWitness(&assignment, curveID.ScalarField())
	if err != nil {
		return nil, err
	}

	return witness, nil
}
