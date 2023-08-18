package main

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/sw_bls12377"
	"github.com/consensys/gnark/std/commitments/kzg_bls12377"
	"github.com/consensys/gnark/std/hash/mimc"
)

var curveID = ecc.BW6_761
var hashID = hash.MIMC_BW6_761

const (
	InputSize = 1
)

var (
	depth    = 5
	numNodes = 1 << depth
)

type Circuit struct {
	MerkleProofs [InputSize]MerkleCircuit
	Commitments  [InputSize]sw_bls12377.G1Affine
	Proof        kzg_bls12377.OpeningProof
	Random       frontend.Variable `gnark:",public"`
	VerifyKey    kzg_bls12377.VK   `gnark:",public"`
	MerkleRoot   frontend.Variable `gnark:",public"`
	NodeCount    frontend.Variable `gnark:",public"`
}

func (circuit *Circuit) allocate() {
	for i := 0; i < InputSize; i++ {
		circuit.MerkleProofs[i].Path = make([]frontend.Variable, depth+1)
	}
}

func (circuit *Circuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	api.Println("res: ", circuit.Random)
	rnd := frontend.Variable(circuit.Random)
	for i := 0; i < InputSize; i++ {
		res := api.And(circuit.NodeCount, rnd)
		api.AssertIsEqual(res, circuit.MerkleProofs[i].Leaf)
		api.Println("res: ", circuit.MerkleProofs[i].Leaf)
		api.Println("res: ", res)

		h.Reset()
		h.Write(circuit.Commitments[i].X)
		h.Write(circuit.Commitments[i].Y)

		api.AssertIsEqual(circuit.MerkleProofs[i].Path[0], h.Sum())

		circuit.MerkleProofs[i].VerifyProof(api, &h, circuit.MerkleRoot)
		if i != 0 {
			circuit.Commitments[0].AddAssign(api, circuit.Commitments[i])
		}
		rnd = api.Mul(rnd, rnd)
	}

	kzg_bls12377.Verify(api, circuit.Commitments[0], circuit.Proof, circuit.Random, circuit.VerifyKey)
	return nil
}

func GenWithness() (witness.Witness, error) {
	var assignment Circuit
	pk, err := GenKey()
	if err != nil {
		return nil, err
	}

	assignment.VerifyKey.G1.Assign(&pk.SRS.G1[0])
	assignment.VerifyKey.G2[0].Assign(&pk.SRS.G2[0])
	assignment.VerifyKey.G2[1].Assign(&pk.SRS.G2[1])

	assignment.NodeCount = numNodes - 1

	mod := curveID.ScalarField()
	fieldSize := len(mod.Bytes())

	fmt.Printf("node count: %d, field size %d\n", numNodes, fieldSize)

	comData := make([]byte, 0, numNodes*fieldSize)
	coms := make([]G1, numNodes)
	pfs := make([]Proof, numNodes)

	var rnd Fr
	rnd.SetInt64(64 + 16 + 3)
	rndBig := new(big.Int)
	rnd.BigInt(rndBig)
	assignment.Random = rndBig

	choose := new(big.Int).Set(rndBig)

	h := hashID.New()

	var accProof Proof
	for i := 0; i < int(numNodes); i++ {
		data := genRandom(1 * MaxFileSize)
		com, err := pk.Commitment(data)
		if err != nil {
			return nil, err
		}

		pf, err := pk.Open(rnd, data)
		if err != nil {
			return nil, err
		}

		err = pk.Verify(rnd, com, pf)
		if err != nil {
			return nil, err
		}
		pfs[i] = pf
		coms[i].Set(&com)

		h.Reset()
		h.Write(com.X.Marshal())
		h.Write(com.Y.Marshal())

		comData = append(comData, h.Sum(nil)...)
	}

	var accCom G1
	for i := 0; i < InputSize; i++ {

		choosed := new(big.Int).And(choose, new(big.Int).SetInt64(int64(numNodes-1)))
		pindex := choosed.Uint64()
		fmt.Printf("choose point %d %d %v\n", i, pindex, choose)
		choose.Mul(choose, choose)

		assignment.Commitments[i].Assign(&coms[pindex])
		accCom.Add(&accCom, &coms[pindex])

		accProof.ClaimedValue.Add(&accProof.ClaimedValue, &pfs[pindex].ClaimedValue)
		accProof.H.Add(&accProof.H, &pfs[pindex].H)

		buf := bytes.NewBuffer(comData)
		merkleRoot, merkleProof, numLeaves, err := merkletree.BuildReaderProof(buf, hashID.New(), fieldSize, pindex)
		if err != nil {
			return nil, err
		}

		fmt.Printf("merkle index %d, depth %d leaf %d, root %d\n", pindex, len(merkleProof), len(merkleProof[0]), len(merkleRoot))

		verified := merkletree.VerifyProof(hashID.New(), merkleRoot, merkleProof, pindex, numLeaves)
		if !verified {
			fmt.Printf("The merkle proof in plain go should pass")
		}

		assignment.MerkleRoot = merkleRoot
		assignment.MerkleProofs[i].Leaf = pindex
		assignment.MerkleProofs[i].Path = make([]frontend.Variable, depth+1)
		for j := 0; j < depth+1; j++ {
			assignment.MerkleProofs[i].Path[j] = merkleProof[j]
		}
	}

	err = pk.Verify(rnd, accCom, accProof)
	if err != nil {
		return nil, err
	}

	claimBig := new(big.Int)
	accProof.ClaimedValue.BigInt(claimBig)
	assignment.Proof.ClaimedValue = claimBig
	assignment.Proof.H.Assign(&accProof.H)

	witness, err := frontend.NewWitness(&assignment, curveID.ScalarField())
	if err != nil {
		return nil, err
	}

	return witness, nil
}
