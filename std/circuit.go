package main

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
)

var curveID = ecc.BN254

type Circuit struct {
	Input frontend.Variable
	Root  frontend.Variable `gnark:",public"`
}

func (circuit *Circuit) Define(api frontend.API) error {
	api.AssertIsEqual(circuit.Input, circuit.Root)
	return nil
}

func GenWithness() (witness.Witness, error) {
	test := big.NewInt(100)

	var assignment Circuit
	assignment.Input = test
	assignment.Root = test

	witness, err := frontend.NewWitness(&assignment, curveID.ScalarField())
	if err != nil {
		return nil, err
	}

	return witness, nil
}
