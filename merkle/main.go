package main

import (
	"fmt"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func main() {
	witness, err := GenWithness()
	if err != nil {
		fmt.Printf("create witness fail: %s\n", err)
		return
	}

	var circuit Circuit
	r1cs, err := frontend.Compile(curveID.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Printf("compile fail: %v\n", err)
		return
	}

	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		fmt.Printf("setup fail: %v\n", err)
		return
	}

	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		fmt.Printf("prove fail: %v\n", err)
		return
	}

	publicWitness, err := witness.Public()
	if err != nil {
		fmt.Printf("get public witness fail: %v\n", err)
		return
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Printf("verification fail: %v\n", err)
		return
	}
	fmt.Printf("verification succeded\n")
}
