package main

import (
	"bytes"
	"crypto/rand"
	"fmt"

	"github.com/yydfjt/gnark-example/lib/merkletree"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/yydfjt/gnark-example/lib/merklecircuit"
)

var curveID = ecc.BN254
var hashID = hash.MIMC_BN254

const (
	Depth = 5
)

var numNodes = 1<<5 + 8
var proofIndex = 1<<5 + 5

var depth int

type Circuit struct {
	M    merklecircuit.Circuit
	Root frontend.Variable `gnark:",public"`
}

func (circuit *Circuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	circuit.M.VerifyProof(api, &h, circuit.Root)

	return nil
}

func GenWithness() (witness.Witness, error) {
	var buf bytes.Buffer

	mod := curveID.ScalarField()
	fieldSize := len(mod.Bytes())

	fmt.Printf("nodes: %d, field size: %d\n", numNodes, fieldSize)

	for i := 0; i < numNodes; i++ {
		leaf, _ := rand.Int(rand.Reader, mod)
		b := leaf.Bytes()
		buf.Write(make([]byte, fieldSize-len(b)))
		buf.Write(b)
	}

	merkleRoot, merkleProof, _, err := merkletree.BuildReaderProof(&buf, hashID.New(), fieldSize, uint64(proofIndex))
	if err != nil {
		return nil, err
	}

	verified := merkletree.VerifyProof(hashID.New(), merkleRoot, merkleProof, uint64(proofIndex))
	if !verified {
		fmt.Printf("The merkle proof in plain go should pass")
	}

	depth = len(merkleProof)
	fmt.Printf("pindex:%d, depth: %d\n", proofIndex, depth)

	var assignment Circuit
	assignment.Root = merkleRoot
	assignment.M.Leaf = proofIndex
	for i := 0; i < depth; i++ {
		assignment.M.Path[i] = merkleProof[i]
	}

	witness, err := frontend.NewWitness(&assignment, curveID.ScalarField())
	if err != nil {
		return nil, err
	}

	return witness, nil
}
