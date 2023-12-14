package main

import (
	"fmt"
	"math/big"
	"math/rand"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

var innerID = ecc.BLS12_377
var innerHashID = hash.MIMC_BLS12_377

var outerID = ecc.BW6_761

const Max = 64

type inCircuit struct {
	Length frontend.Variable `gnark:",public"`
	Point  frontend.Variable `gnark:",public"`
	Seed   frontend.Variable `gnark:",public"`
	Eval   frontend.Variable `gnark:",public"`
}

func (c *inCircuit) Define(api frontend.API) error {
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

type outCircuit struct {
	InnerProof Proof
	InnerVK    VerifyingKey      `gnark:",public"`
	Length     frontend.Variable `gnark:",public"`
	Point      frontend.Variable `gnark:",public"`
	Seed       frontend.Variable `gnark:",public"`
	Eval       frontend.Variable `gnark:",public"`
}

func (c *outCircuit) Define(api frontend.API) error {
	Verify(api, c.InnerVK, c.InnerProof, []frontend.Variable{c.Length, c.Point, c.Seed, c.Eval})

	return nil
}

func GenWithness() (witness.Witness, inCircuit, error) {
	var assignment inCircuit

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

	h := innerHashID.New()
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

	witness, err := frontend.NewWitness(&assignment, innerID.ScalarField())
	if err != nil {
		return nil, assignment, err
	}

	return witness, assignment, nil
}

func GenOutWithness(inc inCircuit, pf groth16.Proof, vk groth16.VerifyingKey) (witness.Witness, error) {
	var assignment outCircuit

	assignment.Length = inc.Length
	assignment.Point = inc.Point
	assignment.Eval = inc.Eval
	assignment.Seed = inc.Seed

	assignment.InnerProof.Assign(pf)
	assignment.InnerVK.Assign(vk)

	witness, err := frontend.NewWitness(&assignment, outerID.ScalarField())
	if err != nil {
		return nil, err
	}

	return witness, nil
}
