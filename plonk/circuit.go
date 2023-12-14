package main

import (
	"fmt"
	"math/big"
	"math/rand"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

var curveID = ecc.BLS12_377
var hashID = hash.MIMC_BLS12_377

const Max = 1000

type Circuit struct {
	Length frontend.Variable `gnark:",public"`
	Point  frontend.Variable `gnark:",public"`
	Seed   frontend.Variable `gnark:",public"`
	Eval   frontend.Variable `gnark:",public"`
}

func (c *Circuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	api.AssertIsLessOrEqual(c.Length, Max)

	sum := frontend.Variable(0)
	coe := frontend.Variable(1)
	for i := 0; i < Max; i++ {
		h.Reset()
		h.Write(c.Seed)
		c.Seed = h.Sum()
		tmp := api.Mul(c.Seed, coe)
		sum = api.Add(sum, tmp)

		tmp = api.Sub(i+1, c.Length)
		tmp = api.IsZero(tmp)
		c.Point = api.Select(tmp, 0, c.Point)

		coe = api.Mul(coe, c.Point)
	}
	api.AssertIsEqual(sum, c.Eval)

	return nil
}

func GenWithness() (witness.Witness, error) {
	var assignment Circuit

	var tmp, sum, seed, point, coe fr.Element
	coe.SetOne()
	seed.SetRandom()
	point.SetRandom()
	pointbig := new(big.Int)
	point.BigInt(pointbig)
	assignment.Point = pointbig
	seedbig := new(big.Int)
	seed.BigInt(seedbig)
	assignment.Seed = seedbig

	h := hashID.New()
	seedbyte := seed.Marshal()

	length := rand.Intn(Max)
	assignment.Length = length

	fmt.Println("choose: ", Max, length)

	for i := 0; i < length; i++ {
		h.Reset()
		h.Write(seedbyte)
		seedbyte = h.Sum(nil)
		tmp.SetBytes(seedbyte)
		tmp.Mul(&tmp, &coe)
		sum.Add(&sum, &tmp)

		coe.Mul(&coe, &point)
	}

	evalbig := new(big.Int)
	sum.BigInt(evalbig)
	assignment.Eval = evalbig

	witness, err := frontend.NewWitness(&assignment, curveID.ScalarField())
	if err != nil {
		return nil, err
	}

	return witness, nil
}
