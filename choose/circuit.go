package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/bits"
)

var curveID = ecc.BW6_761
var hashID = hash.MIMC_BW6_761

const (
	InputSize = 3
	Depth     = 5
)

var max = new(big.Int).SetInt64(1<<Depth - 1)

type Circuit struct {
	Choose [InputSize]frontend.Variable
	Random frontend.Variable `gnark:",public"`
	Max    frontend.Variable `gnark:",public"`
}

func (circuit *Circuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	maxBits := api.ToBinary(circuit.Max, Depth)
	//api.Println(maxBits)

	res := frontend.Variable(circuit.Random)
	for i := 0; i < InputSize; i++ {
		h.Reset()
		h.Write(res)
		res = h.Sum()

		rndbit := api.ToBinary(res)
		for j := 0; j < Depth; j++ {
			rndbit[j] = api.And(rndbit[j], maxBits[j])
		}

		d := bits.FromBinary(api, rndbit[:Depth])

		//api.Println(circuit.Random, res, circuit.Choose[i])
		api.AssertIsEqual(circuit.Choose[i], d)
	}

	return nil
}

func GenWithness() (witness.Witness, error) {
	var assignment Circuit

	mod := curveID.ScalarField()
	fieldSize := len(mod.Bytes())

	h := hashID.New()

	rnd, err := rand.Int(rand.Reader, mod)
	if err != nil {
		return nil, err
	}

	assignment.Random = new(big.Int).Set(rnd)
	assignment.Max = new(big.Int).Set(max)

	for i := 0; i < InputSize; i++ {
		h.Reset()
		var buf bytes.Buffer
		buf.Write(make([]byte, fieldSize-len(rnd.Bytes())))
		buf.Write(rnd.Bytes())

		h.Write(buf.Bytes())
		sum := h.Sum(nil)
		rnd.SetBytes(sum)

		choosed := new(big.Int).And(rnd, max)

		fmt.Println("choose: ", choosed, rnd)
		assignment.Choose[i] = choosed
	}

	witness, err := frontend.NewWitness(&assignment, curveID.ScalarField())
	if err != nil {
		return nil, err
	}

	return witness, nil
}
