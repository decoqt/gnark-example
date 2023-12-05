package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

var curveID = ecc.BW6_761
var hashID = hash.MIMC_BW6_761

const (
	InputSize = 3
	Depth     = 5
)

var max = new(big.Int).SetInt64(1<<Depth + 11)

func init() {
	solver.RegisterHint(ModHint)
}

func ModHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	for i := 0; i < len(results); i++ {
		results[i].Mod(inputs[i+1], inputs[0])
	}
	return nil
}

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

	res := frontend.Variable(circuit.Random)
	for i := 0; i < InputSize; i++ {
		h.Reset()
		h.Write(res)
		res = h.Sum()

		resbig, err := api.Compiler().NewHint(ModHint, 1, circuit.Max, res)
		if err != nil {
			panic(err)
		}

		//api.Println(res, resbig[0], circuit.Choose[i])
		api.AssertIsLessOrEqual(circuit.Choose[i], circuit.Max)
		api.AssertIsEqual(circuit.Choose[i], resbig[0])
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

		choosed := new(big.Int).Mod(rnd, max)

		fmt.Println("choose: ", choosed, rnd)
		assignment.Choose[i] = choosed
	}

	witness, err := frontend.NewWitness(&assignment, curveID.ScalarField())
	if err != nil {
		return nil, err
	}

	return witness, nil
}
