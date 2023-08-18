package main

import (
	"bytes"
	"crypto/rand"
	"fmt"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/hash/mimc"
)

var curveID = ecc.BN254
var hashID = hash.MIMC_BN254

var numNodes = 64
var proofIndex = 9

var depth int

type Circuit struct {
	M    merkle.MerkleProof
	Leaf frontend.Variable
}

// pre allocate slice
func (circuit *Circuit) allocate() error {
	circuit.M.Path = make([]frontend.Variable, depth)
	return nil
}

func (circuit *Circuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	circuit.M.VerifyProof(api, &h, circuit.Leaf)

	return nil
}

func GenWithness() (witness.Witness, error) {
	var buf bytes.Buffer

	mod := curveID.ScalarField()
	fieldSize := len(mod.Bytes())

	fmt.Println("field size: ", fieldSize)

	for i := 0; i < numNodes; i++ {
		leaf, _ := rand.Int(rand.Reader, mod)
		b := leaf.Bytes()
		buf.Write(make([]byte, fieldSize-len(b)))
		buf.Write(b)
	}

	merkleRoot, merkleProof, numLeaves, err := merkletree.BuildReaderProof(&buf, hashID.New(), fieldSize, uint64(proofIndex))
	if err != nil {
		return nil, err
	}

	verified := merkletree.VerifyProof(hashID.New(), merkleRoot, merkleProof, uint64(proofIndex), numLeaves)
	if !verified {
		fmt.Printf("The merkle proof in plain go should pass")
	}

	depth = len(merkleProof)

	var assignment Circuit
	assignment.Leaf = proofIndex
	assignment.M.RootHash = merkleRoot
	assignment.M.Path = make([]frontend.Variable, depth)
	for i := 0; i < depth; i++ {
		assignment.M.Path[i] = merkleProof[i]
	}

	witness, err := frontend.NewWitness(&assignment, curveID.ScalarField())
	if err != nil {
		return nil, err
	}

	return witness, nil
}
