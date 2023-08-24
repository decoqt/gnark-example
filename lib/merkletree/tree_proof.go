// Package merkletree provides Merkle tree and proof following RFC 6962.
//
// From https://gitlab.com/NebulousLabs/merkletree
package merkletree

import (
	"errors"
	"hash"
)

type ProofTree struct {
	head *subTree
	hash hash.Hash

	currentIndex uint64
	proofIndex   uint64
	proofSet     [][]byte
	proofTree    bool
}

type subTree struct {
	next   *subTree
	height int // Int is okay because a height over 300 is physically unachievable.
	sum    []byte
}

// sum returns the hash of the input data using the specified algorithm.
func sum(h hash.Hash, data ...[]byte) []byte {
	h.Reset()
	for _, d := range data {
		// the Hash interface specifies that Write never returns an error
		_, err := h.Write(d)
		if err != nil {
			panic(err)
		}
	}
	return h.Sum(nil)
}

func leafSum(h hash.Hash, data []byte) []byte {
	return sum(h, data)
}

func nodeSum(h hash.Hash, a, b []byte) []byte {
	return sum(h, a, b)
}

// joinSubTrees combines two equal sized subTrees into a larger subTree.
func joinSubTrees(h hash.Hash, a, b *subTree) *subTree {
	return &subTree{
		next:   a.next,
		height: a.height + 1,
		sum:    nodeSum(h, a.sum, b.sum),
	}
}

func New(h hash.Hash) *ProofTree {
	return &ProofTree{
		hash: h,
	}
}

func (t *ProofTree) Push(data []byte) {
	if t.currentIndex == t.proofIndex {
		t.proofSet = append(t.proofSet, data)
	}

	t.head = &subTree{
		next:   t.head,
		height: 0,
		sum:    leafSum(t.hash, data),
	}

	t.joinAllSubTrees()

	t.currentIndex++
}

func (t *ProofTree) SetIndex(i uint64) error {
	if t.head != nil {
		return errors.New("cannot call SetIndex on ProofTree if ProofTree has not been reset")
	}
	t.proofTree = true
	t.proofIndex = i
	return nil
}

func (t *ProofTree) joinAllSubTrees() {
	for t.head.next != nil && t.head.height == t.head.next.height {
		if t.head.height == len(t.proofSet)-1 {
			leaves := uint64(1 << uint(t.head.height))
			mid := (t.currentIndex / leaves) * leaves
			if t.proofIndex < mid {
				t.proofSet = append(t.proofSet, t.head.sum)
			} else {
				t.proofSet = append(t.proofSet, t.head.next.sum)
			}
		}

		t.head = joinSubTrees(t.hash, t.head.next, t.head)
	}
}

func (t *ProofTree) joinAndFillSubTrees(h hash.Hash, a, b *subTree, proofSet [][]byte) (*subTree, [][]byte) {
	nb := &subTree{
		height: b.height,
		sum:    make([]byte, len(b.sum)),
	}
	copy(nb.sum, b.sum)

	for nb.height < a.height {
		//fmt.Printf("start: %d, height:%d, plen: %d\n", b.height, nb.height, len(proofSet)-1)
		if nb.height == len(proofSet)-1 {
			proofSet = append(proofSet, nb.sum)
		}
		nb.sum = nodeSum(h, nb.sum, nb.sum)
		nb.height++
	}

	//fmt.Printf("height:%d, plen: %d\n", nb.height, len(proofSet)-1)
	if nb.height == len(proofSet)-1 {
		leaves := uint64(1 << uint(nb.height))
		mid := (t.currentIndex / leaves) * leaves
		if t.proofIndex < mid {
			proofSet = append(proofSet, nb.sum)
		} else {
			proofSet = append(proofSet, a.sum)
		}
	}

	return &subTree{
		next:   a.next,
		height: a.height + 1,
		sum:    nodeSum(h, a.sum, nb.sum),
	}, proofSet
}

func (t *ProofTree) Root() []byte {
	if t.head == nil {
		return nil
	}
	current := t.head
	for current.next != nil {
		current, _ = t.joinAndFillSubTrees(t.hash, current.next, current, nil)
	}
	// Return a copy to prevent leaking a pointer to internal data.
	return append(current.sum[:0:0], current.sum...)
}

func (t *ProofTree) Prove() (merkleRoot []byte, proofSet [][]byte, proofIndex uint64, numLeaves uint64) {
	if !t.proofTree {
		panic("wrong usage: can't call prove on a tree if SetIndex wasn't called")
	}

	// Return nil if the ProofTree is empty, or if the proofIndex hasn't yet been
	// reached.
	if t.head == nil || len(t.proofSet) == 0 {
		return t.Root(), nil, t.proofIndex, t.currentIndex
	}
	proofSet = t.proofSet

	//fmt.Println("len: ", len(t.proofSet), len(proofSet))

	current := t.head
	for current.next != nil {
		current, proofSet = t.joinAndFillSubTrees(t.hash, current.next, current, proofSet)
		//fmt.Println("len: ", len(t.proofSet), len(proofSet))
	}

	return current.sum, proofSet, t.proofIndex, t.currentIndex
}
