package main

import (
	"fmt"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func main() {
	witness, inc, err := GenWithness()
	if err != nil {
		fmt.Printf("create witness fail: %s\n", err)
		return
	}

	var circuit inCircuit
	incs, err := frontend.Compile(innerID.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Printf("compile fail: %v\n", err)
		return
	}

	inpk, invk, err := groth16.Setup(incs)
	if err != nil {
		fmt.Printf("setup fail: %v\n", err)
		return
	}

	inproof, err := groth16.Prove(incs, inpk, witness)
	if err != nil {
		fmt.Printf("prove fail: %v\n", err)
		return
	}

	publicWitness, err := witness.Public()
	if err != nil {
		fmt.Printf("get public witness fail: %v\n", err)
		return
	}

	err = groth16.Verify(inproof, invk, publicWitness)
	if err != nil {
		fmt.Printf("verification fail: %v\n", err)
		return
	}
	fmt.Printf("verification inner succeded\n")

	var outcircuit outCircuit
	outcircuit.InnerVK.Allocate(invk)
	outcs, err := frontend.Compile(outerID.ScalarField(), r1cs.NewBuilder, &outcircuit)
	if err != nil {
		fmt.Printf("out compile fail: %v\n", err)
		return
	}

	outpk, outvk, err := groth16.Setup(outcs)
	if err != nil {
		fmt.Printf("out setup fail: %v\n", err)
		return
	}

	outw, err := GenOutWithness(inc, inproof, invk)
	if err != nil {
		fmt.Printf("out witness fail: %v\n", err)
		return
	}

	outproof, err := groth16.Prove(outcs, outpk, outw)
	if err != nil {
		fmt.Printf("out prove fail: %v\n", err)
		return
	}

	outpublicWitness, err := outw.Public()
	if err != nil {
		fmt.Printf("out get public witness fail: %v\n", err)
		return
	}

	err = groth16.Verify(outproof, outvk, outpublicWitness)
	if err != nil {
		fmt.Printf("out verification fail: %v\n", err)
		return
	}
	fmt.Printf("out verification inner succeded\n")
}
