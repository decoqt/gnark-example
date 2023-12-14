package main

import (
	"fmt"

	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

func main() {
	witness, err := GenWithness()
	if err != nil {
		fmt.Printf("create witness fail: %s\n", err)
		return
	}

	var circuit Circuit
	r1cs, err := frontend.Compile(curveID.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		fmt.Printf("compile fail: %v\n", err)
		return
	}

	srs, srsl, err := unsafekzg.NewSRS(r1cs)
	if err != nil {
		fmt.Printf("kzg fail: %v\n", err)
		return
	}

	pk, vk, err := plonk.Setup(r1cs, srs, srsl)
	if err != nil {
		fmt.Printf("setup fail: %v\n", err)
		return
	}

	proof, err := plonk.Prove(r1cs, pk, witness)
	if err != nil {
		fmt.Printf("prove fail: %v\n", err)
		return
	}

	publicWitness, err := witness.Public()
	if err != nil {
		fmt.Printf("get public witness fail: %v\n", err)
		return
	}

	err = plonk.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Printf("verification fail: %v\n", err)
		return
	}
	fmt.Printf("verification succeded\n")
}
