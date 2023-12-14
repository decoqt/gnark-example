package main

import (
	"fmt"
	"math/big"
	"math/rand"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/emulated"
	stdplonk "github.com/consensys/gnark/std/recursion/plonk"
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

type outCircuit[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        stdplonk.Proof[FR, G1El, G2El]
	VerifyingKey stdplonk.VerifyingKey[FR, G1El, G2El] `gnark:",public"`
	InnerWitness stdplonk.Witness[FR]                  `gnark:",public"`
}

func (c *outCircuit[FR, G1El, G2El, GtEl]) Define(api frontend.API) error {
	verifier, err := stdplonk.NewVerifier[FR, G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	err = verifier.AssertProof(c.VerifyingKey, c.Proof, c.InnerWitness)
	return err
}

func GenWithness() (witness.Witness, error) {
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
		return nil, err
	}

	return witness, nil
}

func GenOutWitness(innerWitness witness.Witness, innerProof plonk.Proof, innerVK plonk.VerifyingKey) (witness.Witness, error) {
	circuitVk, err := stdplonk.ValueOfVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerVK)
	if err != nil {
		panic(err)
	}
	circuitWitness, err := stdplonk.ValueOfWitness[sw_bls12377.ScalarField](innerWitness)
	if err != nil {
		panic(err)
	}
	circuitProof, err := stdplonk.ValueOfProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProof)
	if err != nil {
		panic(err)
	}

	assignment := &outCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: circuitWitness,
		Proof:        circuitProof,
		VerifyingKey: circuitVk,
	}

	witness, err := frontend.NewWitness(assignment, outerID.ScalarField())
	if err != nil {
		return nil, err
	}

	return witness, nil
}
