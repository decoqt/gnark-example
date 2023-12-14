package main

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/yydfjt/gnark-example/lib/kzg"
	"github.com/yydfjt/gnark-example/lib/merklecircuit"
	"github.com/yydfjt/gnark-example/lib/merkletree"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/bits"
)

var curveID = ecc.BW6_761
var hashID = hash.MIMC_BW6_761

const (
	InputSize = 2
	Depth     = 5
)

var (
	maxNodes = 1 << Depth
)

type Circuit struct {
	MerkleProofs [InputSize]merklecircuit.Circuit
	Commitments  [InputSize]sw_bls12377.G1Affine
	Proof        kzg.OpeningProof
	VerifyKey    kzg.VK            `gnark:",public"`
	Random       frontend.Variable `gnark:",public"`
	MerkleRoot   frontend.Variable `gnark:",public"`
	Max          frontend.Variable `gnark:",public"`
}

func (circuit *Circuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	api.Println(circuit.MerkleRoot)
	maxBits := api.ToBinary(circuit.Max, Depth)
	rnd := frontend.Variable(circuit.Random)
	for i := 0; i < InputSize; i++ {
		h.Reset()
		h.Write(rnd)
		rnd = h.Sum()
		rndbit := api.ToBinary(rnd)
		for j := 0; j < Depth; j++ {
			rndbit[j] = api.And(rndbit[j], maxBits[j])
		}
		d := bits.FromBinary(api, rndbit[:Depth])
		api.AssertIsEqual(circuit.MerkleProofs[i].Leaf, d)

		h.Reset()
		h.Write(circuit.Commitments[i].X)
		h.Write(circuit.Commitments[i].Y)

		api.AssertIsEqual(circuit.MerkleProofs[i].Path[0], h.Sum())

		circuit.MerkleProofs[i].VerifyProof(api, &h, circuit.MerkleRoot)
		if i != 0 {
			circuit.Commitments[0].AddAssign(api, circuit.Commitments[i])
		}
	}

	kzg.Verify(api, circuit.Commitments[0], circuit.Proof, circuit.Random, circuit.VerifyKey)
	return nil
}

func GenWithness() (witness.Witness, error) {
	var assignment Circuit
	pk, err := kzg.GenKey()
	if err != nil {
		return nil, err
	}

	assignment.VerifyKey.G1.Assign(&pk.Vk.G1)
	assignment.VerifyKey.G2[0] = sw_bls12377.NewG2Affine(pk.Vk.G2[0])
	assignment.VerifyKey.G2[1] = sw_bls12377.NewG2Affine(pk.Vk.G2[1])

	mod := curveID.ScalarField()
	fieldSize := len(mod.Bytes())

	fmt.Printf("node count: %d, field size %d\n", maxNodes, fieldSize)

	comData := make([]byte, 0, maxNodes*fieldSize)
	coms := make([]kzg.G1, maxNodes)
	pfs := make([]kzg.Proof, maxNodes)

	var rndfr kzg.Fr
	rndfr.SetRandom()
	rndBig := new(big.Int)
	rndfr.BigInt(rndBig)
	assignment.Random = rndBig

	h := hashID.New()

	var accProof kzg.Proof
	for i := 0; i < int(maxNodes); i++ {
		data := kzg.GenRandom(1 * kzg.MaxFileSize)
		com, err := pk.Commitment(data)
		if err != nil {
			return nil, err
		}

		pf, err := pk.Open(rndfr, data)
		if err != nil {
			return nil, err
		}

		err = pk.Verify(rndfr, com, pf)
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

	max := new(big.Int).SetUint64(uint64(maxNodes - 1))
	assignment.Max = new(big.Int).Set(max)

	var accCom kzg.G1
	rnd := new(big.Int).Set(rndBig)
	for i := 0; i < InputSize; i++ {
		h.Reset()
		var rbuf bytes.Buffer
		rbuf.Write(make([]byte, fieldSize-len(rnd.Bytes())))
		rbuf.Write(rnd.Bytes())
		h.Write(rbuf.Bytes())
		sum := h.Sum(nil)
		rnd.SetBytes(sum)

		choosed := new(big.Int).And(rnd, max)
		pindex := choosed.Uint64()
		fmt.Printf("choose point %d %d \n", i, pindex)

		assignment.Commitments[i].Assign(&coms[pindex])
		accCom.Add(&accCom, &coms[pindex])

		accProof.ClaimedValue.Add(&accProof.ClaimedValue, &pfs[pindex].ClaimedValue)
		accProof.H.Add(&accProof.H, &pfs[pindex].H)

		buf := bytes.NewBuffer(comData)
		merkleRoot, merkleProof, _, err := merkletree.BuildReaderProof(buf, hashID.New(), fieldSize, pindex)
		if err != nil {
			return nil, err
		}

		fmt.Printf("merkle index %d, depth %d leaf %d, root %d\n", pindex, len(merkleProof), len(merkleProof[0]), len(merkleRoot))

		verified := merkletree.VerifyProof(hashID.New(), merkleRoot, merkleProof, pindex)
		if !verified {
			return nil, fmt.Errorf("invalid merkle proof")
		}

		assignment.MerkleRoot = merkleRoot
		assignment.MerkleProofs[i].Leaf = pindex
		for j := 0; j < len(assignment.MerkleProofs[i].Path); j++ {
			if j < len(merkleProof) {
				fmt.Println(new(big.Int).SetBytes(merkleProof[j]).String())
				assignment.MerkleProofs[i].Path[j] = merkleProof[j]
			} else {
				assignment.MerkleProofs[i].Path[j] = 0
			}
		}
	}

	err = pk.Verify(rndfr, accCom, accProof)
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
