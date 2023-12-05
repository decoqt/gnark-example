package main

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/hash/mimc"
)

var curveID = ecc.BW6_761

const (
	DepthC1          = 10
	ChallengeCountC1 = 16
)

func init() {
	solver.RegisterHint(ModHint)
}

func ModHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	for i := 0; i < len(results); i++ {
		results[i].Mod(inputs[i+1], inputs[0])
	}
	return nil
}

type MerkleC1 struct {
	Leaf frontend.Variable
	Path [DepthC1 + 1]frontend.Variable
}

func leafSum(api frontend.API, h hash.FieldHasher, data frontend.Variable) frontend.Variable {
	h.Reset()
	h.Write(data)
	res := h.Sum()
	return res
}

func nodeSum(api frontend.API, h hash.FieldHasher, a, b frontend.Variable) frontend.Variable {
	h.Reset()
	h.Write(a, b)
	res := h.Sum()
	return res
}

func (mc1 *MerkleC1) VerifyProof(api frontend.API, h hash.FieldHasher, root frontend.Variable) {
	sum := leafSum(api, h, mc1.Path[0])

	binLeaf := api.ToBinary(mc1.Leaf, DepthC1)
	for i := 1; i < DepthC1; i++ { // the size of the loop is fixed -> one circuit per size
		d1 := api.Select(binLeaf[i-1], mc1.Path[i], sum)
		d2 := api.Select(binLeaf[i-1], sum, mc1.Path[i])
		update := nodeSum(api, h, d1, d2)
		isZero := api.IsZero(mc1.Path[i])
		sum = api.Select(isZero, sum, update) // for fixed depth
	}

	// Compare our calculated Merkle root to the desired Merkle root.
	api.AssertIsEqual(sum, root)
}

type VK struct {
	G1 sw_bls12377.G1Affine    // G₁
	G2 [2]sw_bls12377.G2Affine // [G₂, [α]G₂]
}

type C1 struct {
	MerkleProof  [ChallengeCountC1]MerkleC1
	CommitRoot   sw_bls12377.G1Affine                   `gnark:",public"`
	RecoveryRoot sw_bls12377.G1Affine                   `gnark:",public"`
	MerkleRoot   frontend.Variable                      `gnark:",public"`
	Offset       frontend.Variable                      `gnark:",public"`
	Max          frontend.Variable                      `gnark:",public"`
	VK           VK                                     `gnark:",public"`
	VKG2         [ChallengeCountC1]sw_bls12377.G2Affine `gnark:",public"`
	VKGT         sw_bls12377.GT                         `gnark:",public"`
}

func (c *C1) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	h.Write(c.MerkleRoot)
	h.Write(c.CommitRoot)
	rnd := h.Sum()

	// generate
	for i := 0; i < ChallengeCountC1; i++ {
		h.Reset()
		h.Write(rnd)
		h.Write(i)
		choosed, err := api.Compiler().NewHint(ModHint, 1, c.Max, h.Sum)
		if err != nil {
			panic(err)
		}

		// verify merkle leaf
		api.AssertIsEqual(c.MerkleProof[i].Leaf, choosed)
		// verify merkle proof
		c.MerkleProof[i].VerifyProof(api, &h, c.MerkleRoot)
		// verify value is same
		//api.AssertIsEqual(c.MerkleProof[i].Path[0], c.PointProof[i].ClaimedValue)
		// verify point proof
		//VerifyPoint(api, c.CommitRoot, c.PointProof[i], c.VK.G2[0], c.VKG2[i], c.VKGT)
	}

	// verify move proof
	//VerifyMove(api, &h, c.RecoveryRoot, c.CommitRoot, c.MoveProof, c.Offset, c.VK)

	return nil
}

func GenC1() (witness.Witness, error) {
	var assignment C1

	witness, err := frontend.NewWitness(&assignment, curveID.ScalarField())
	if err != nil {
		return nil, err
	}
	return witness, nil
}

func Run(circuit frontend.Circuit, w witness.Witness) error {
	r1cs, err := frontend.Compile(curveID.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		fmt.Printf("compile fail: %v\n", err)
		return err
	}

	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		fmt.Printf("setup fail: %v\n", err)
		return err
	}

	proof, err := groth16.Prove(r1cs, pk, w)
	if err != nil {
		fmt.Printf("prove fail: %v\n", err)
		return err
	}

	publicWitness, err := w.Public()
	if err != nil {
		fmt.Printf("get public witness fail: %v\n", err)
		return err
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Printf("verification fail: %v\n", err)
		return err
	}
	fmt.Printf("verification succeded\n")
	return nil
}

func main() {
	w, err := GenC1()
	if err != nil {
		return
	}

	var circuit C1
	err = Run(&circuit, w)
	if err != nil {
		return
	}
}
