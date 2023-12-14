package main

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	stdplonk "github.com/consensys/gnark/std/recursion/plonk"
	"github.com/consensys/gnark/test/unsafekzg"
)

func main() {
	witness, err := GenWithness()
	if err != nil {
		fmt.Printf("create witness fail: %s\n", err)
		return
	}

	var circuit inCircuit
	incs, err := frontend.Compile(innerID.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		fmt.Printf("compile fail: %v\n", err)
		return
	}

	kzgsrs, kzgsrsl, err := unsafekzg.NewSRS(incs)
	if err != nil {
		fmt.Printf("kzg fail: %v\n", err)
		return
	}

	inpk, invk, err := plonk.Setup(incs, kzgsrs, kzgsrsl)
	if err != nil {
		fmt.Printf("setup fail: %v\n", err)
		return
	}

	inproof, err := plonk.Prove(incs, inpk, witness, stdplonk.GetNativeProverOptions(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField()))
	if err != nil {
		fmt.Printf("prove fail: %v\n", err)
		return
	}

	publicWitness, err := witness.Public()
	if err != nil {
		fmt.Printf("get public witness fail: %v\n", err)
		return
	}

	err = plonk.Verify(inproof, invk, publicWitness, stdplonk.GetNativeVerifierOptions(ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField()))
	if err != nil {
		fmt.Printf("verification fail: %v\n", err)
		return
	}
	fmt.Printf("verification inner succeded\n")

	outerCircuit := &outCircuit[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		InnerWitness: stdplonk.PlaceholderWitness[sw_bls12377.ScalarField](incs),
		Proof:        stdplonk.PlaceholderProof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](incs),
		VerifyingKey: stdplonk.PlaceholderVerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine](incs),
	}
	outcs, err := frontend.Compile(outerID.ScalarField(), scs.NewBuilder, outerCircuit)
	if err != nil {
		fmt.Printf("out compile fail: %v\n", err)
		return
	}

	outsrs, outsrsl, err := unsafekzg.NewSRS(outcs)
	if err != nil {
		fmt.Printf("kzg fail: %v\n", err)
		return
	}

	outpk, outvk, err := plonk.Setup(outcs, outsrs, outsrsl)
	if err != nil {
		fmt.Printf("out setup fail: %v\n", err)
		return
	}

	outw, err := GenOutWitness(publicWitness, inproof, invk)
	if err != nil {
		fmt.Printf("out witness fail: %v\n", err)
		return
	}

	outproof, err := plonk.Prove(outcs, outpk, outw)
	if err != nil {
		fmt.Printf("out prove fail: %v\n", err)
		return
	}

	outpublicWitness, err := outw.Public()
	if err != nil {
		fmt.Printf("out get public witness fail: %v\n", err)
		return
	}

	err = plonk.Verify(outproof, outvk, outpublicWitness)
	if err != nil {
		fmt.Printf("out verification fail: %v\n", err)
		return
	}
	fmt.Printf("out verification inner succeded\n")
}
