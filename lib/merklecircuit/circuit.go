package merklecircuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
)

const Depth = 10

// MerkleProof stores the path, the root hash and an helper for the Merkle proof.
type Circuit struct {
	// Path path of the Merkle proof
	Leaf frontend.Variable
	Path [Depth + 1]frontend.Variable
}

// leafSum returns the hash created from data inserted to form a leaf.
// Without domain separation.
func leafSum(api frontend.API, h hash.Hash, data frontend.Variable) frontend.Variable {

	h.Reset()
	h.Write(data)
	res := h.Sum()

	return res
}

// nodeSum returns the hash created from data inserted to form a leaf.
// Without domain separation.
func nodeSum(api frontend.API, h hash.Hash, a, b frontend.Variable) frontend.Variable {

	h.Reset()
	h.Write(a, b)
	res := h.Sum()

	return res
}

// VerifyProof takes a Merkle root, a proofSet, and a proofIndex and returns
// true if the first element of the proof set is a leaf of data in the Merkle
// root. False is returned if the proof set or Merkle root is nil, and if
// 'numLeaves' equals 0.
func (mp *Circuit) VerifyProof(api frontend.API, h hash.Hash, root frontend.Variable) {

	depth := len(mp.Path) - 1
	sum := leafSum(api, h, mp.Path[0])

	// The binary decomposition is the bitwise negation of the order of hashes ->
	// If the path in the plain go code is 					0 1 1 0 1 0
	// The binary decomposition of the leaf index will be 	1 0 0 1 0 1 (little endian)
	binLeaf := api.ToBinary(mp.Leaf, depth)

	api.Println("leaf: ", mp.Leaf, binLeaf)
	for i := 1; i < len(mp.Path); i++ { // the size of the loop is fixed -> one circuit per size
		d1 := api.Select(binLeaf[i-1], mp.Path[i], sum)
		d2 := api.Select(binLeaf[i-1], sum, mp.Path[i])
		update := nodeSum(api, h, d1, d2)
		isZero := api.IsZero(mp.Path[i])
		sum = api.Select(isZero, sum, update)
		api.Println("path: ", i, mp.Path[i], sum, update)
	}

	// Compare our calculated Merkle root to the desired Merkle root.
	api.AssertIsEqual(sum, root)
}
