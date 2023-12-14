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
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/hash/mimc"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
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

type outCircuit[S algebra.ScalarT, G1El algebra.G1ElementT, G2El algebra.G2ElementT, GtEl algebra.GtElementT] struct {
	Proof        stdgroth16.Proof[G1El, G2El]
	VerifyingKey stdgroth16.VerifyingKey[G1El, G2El, GtEl]
	InnerWitness stdgroth16.Witness[S]
}

func (c *outCircuit[S, G1El, G2El, GtEl]) Define(api frontend.API) error {
	curve, err := algebra.GetCurve[S, G1El](api)
	if err != nil {
		return fmt.Errorf("new curve: %w", err)
	}
	pairing, err := algebra.GetPairing[G1El, G2El, GtEl](api)
	if err != nil {
		return fmt.Errorf("get pairing: %w", err)
	}
	verifier := stdgroth16.NewVerifier(curve, pairing)
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

func GenOutWitness(innerWitness witness.Witness, innerProof groth16.Proof, innerVK groth16.VerifyingKey) (witness.Witness, error) {
	circuitVk, err := stdgroth16.ValueOfVerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](innerVK)
	if err != nil {
		panic(err)
	}
	circuitWitness, err := stdgroth16.ValueOfWitness[sw_bls12377.Scalar, sw_bls12377.G1Affine](innerWitness)
	if err != nil {
		panic(err)
	}
	circuitProof, err := stdgroth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](innerProof)
	if err != nil {
		panic(err)
	}

	assignment := &outCircuit[sw_bls12377.Scalar, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
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
