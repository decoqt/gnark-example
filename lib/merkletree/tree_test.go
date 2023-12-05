package merkletree

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/rand"
	"testing"
)

var segSize = 32
var depth = 5

func GenRandom(len int) []byte {
	res := make([]byte, len)
	for i := 0; i < len; i += 7 {
		val := rand.Int63()
		for j := 0; i+j < len && j < 7; j++ {
			res[i+j] = byte(val)
			val >>= 8
		}
	}
	return res
}

func TestMerkelTree(t *testing.T) {
	for nc := 1 << depth; nc < (1 << (depth + 1)); nc++ {
		for j := 0; j < nc; j++ {
			tree := New(sha256.New())

			tree.SetIndex(uint64(j))

			for i := 0; i < nc; i++ {
				b := GenRandom(segSize)
				tree.Push(b)
			}

			merkleRoot, merkleProof, pindex, numLeaves := tree.Prove()
			if pindex != uint64(j) {
				t.Fatal("wrong proof index")
			}

			if numLeaves != uint64(nc) {
				t.Fatal("wrong node count")
			}

			if !bytes.Equal(tree.Root(), merkleRoot) {
				t.Fatal("wrong node root")
			}

			t.Logf("prooflen: %d\n", len(merkleProof))
			//t.Log("proot:", hex.EncodeToString(merkleRoot))

			verified := VerifyProof(sha256.New(), merkleRoot, merkleProof, pindex)
			if !verified {
				t.Fatal("wrong merkle proof at: ", j, nc)
			}
		}
	}
}

func TestMerkelProof(t *testing.T) {
	var buf bytes.Buffer

	var numNodes = 1<<5 + 7
	var proofIndex = 1<<5 + 1
	fmt.Printf("nodes: %d, proof index: %d\n", numNodes, proofIndex)

	for i := 0; i < numNodes; i++ {
		b := GenRandom(segSize)
		buf.Write(b)
	}

	merkleRoot, merkleProof, _, err := BuildReaderProof(&buf, sha256.New(), segSize, uint64(proofIndex))
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("prooflen: %d\n", len(merkleProof))

	verified := VerifyProof(sha256.New(), merkleRoot, merkleProof, uint64(proofIndex))
	if !verified {
		t.Fatal("wrong merkle proof")
	}
}

func TestMerkelRoot(t *testing.T) {
	var numNodes = 1<<5 + 1<<4
	fmt.Printf("nodes: %d\n", numNodes)

	t1 := New(sha256.New())
	t2 := NewRTree(sha256.New())

	for i := 0; i < numNodes; i++ {
		b := GenRandom(segSize)
		t1.Push(b)
		t2.Push(b)

		if !bytes.Equal(t1.Root(), t2.Root()) {
			t.Fatal("unequal root at: ", i)
		}
	}

	if !bytes.Equal(t1.Root(), t1.Root()) {
		t.Fatal("unequal root self")
	}

	if !bytes.Equal(t1.Root(), t2.Root()) {
		t.Fatal("unequal root")
	}
}

func TestBits(t *testing.T) {
	pindex := 13

	for i := 0; i < 10; i++ {
		pi := ((pindex & (1 << i)) >> i)
		t.Log(i, pi)
	}
}
