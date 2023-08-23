// Package merkletree provides Merkle tree and proof following RFC 6962.
//
// From https://gitlab.com/NebulousLabs/merkletree
package merkletree

import (
	"bytes"
	"errors"
	"hash"
	"io"
)

func (t *Tree) Legacy_Prove() (merkleRoot []byte, proofSet [][]byte, proofIndex uint64, numLeaves uint64) {
	if !t.proofTree {
		panic("wrong usage: can't call prove on a tree if SetIndex wasn't called")
	}

	// Return nil if the Tree is empty, or if the proofIndex hasn't yet been
	// reached.
	if t.head == nil || len(t.proofSet) == 0 {
		return t.Root(), nil, t.proofIndex, t.currentIndex
	}

	//fmt.Println("prooflen: ", len(t.proofSet))
	proofSet = t.proofSet

	// The set of subtrees must now be collapsed into a single root. The proof
	// set already contains all of the elements that are members of a complete
	// subtree. Of what remains, there will be at most 1 element provided from
	// a sibling on the right, and all of the other proofs will be provided
	// from a sibling on the left. This results from the way orphans are
	// treated. All subtrees smaller than the subtree containing the proofIndex
	// will be combined into a single subtree that gets combined with the
	// proofIndex subtree as a single right sibling. All subtrees larger than
	// the subtree containing the proofIndex will be combined with the subtree
	// containing the proof index as left siblings.

	// Start at the smallest subtree and combine it with larger subtrees until
	// it would be combining with the subtree that contains the proof index. We
	// can recognize the subtree containing the proof index because the height
	// of that subtree will be one less than the current length of the proof
	// set.
	current := t.head
	for current.next != nil && current.next.height < len(proofSet)-1 {
		current = joinSubTrees(t.hash, current.next, current)
	}

	// If the current subtree is not the subtree containing the proof index,
	// then it must be an aggregate subtree that is to the right of the subtree
	// containing the proof index, and the next subtree is the subtree
	// containing the proof index.
	if current.next != nil && current.next.height == len(proofSet)-1 {
		proofSet = append(proofSet, current.sum)
		current = current.next
	}

	// The current subtree must be the subtree containing the proof index. This
	// subtree does not need an entry, as the entry was created during the
	// construction of the Tree. Instead, skip to the next subtree.
	current = current.next

	// All remaining subtrees will be added to the proof set as a left sibling,
	// completing the proof set.
	for current != nil {
		proofSet = append(proofSet, current.sum)
		current = current.next
	}
	return t.Root(), proofSet, t.proofIndex, t.currentIndex
}

func (t *Tree) Legacy_Root() []byte {
	if t.head == nil {
		return nil
	}
	current := t.head
	for current.next != nil {
		current = joinSubTrees(t.hash, current.next, current)
	}
	// Return a copy to prevent leaking a pointer to internal data.
	return append(current.sum[:0:0], current.sum...)
}

func Legacy_BuildReaderProof(r io.Reader, h hash.Hash, segmentSize int, index uint64) (root []byte, proofSet [][]byte, numLeaves uint64, err error) {
	tree := New(h)
	err = tree.SetIndex(index)
	if err != nil {
		// This code should be unreachable - SetIndex will only return an error
		// if the tree is not empty, and yet the tree should be empty at this
		// point.
		panic(err)
	}
	err = tree.ReadAll(r, segmentSize)
	if err != nil {
		return
	}
	root, proofSet, _, numLeaves = tree.Legacy_Prove()
	if len(proofSet) == 0 {
		err = errors.New("index was not reached while creating proof")
		return
	}
	return
}

func Legacy_ReaderRoot(r io.Reader, h hash.Hash, segmentSize int) (root []byte, err error) {
	tree := New(h)
	err = tree.ReadAll(r, segmentSize)
	if err != nil {
		return
	}
	root = tree.Legacy_Root()
	return
}

func Legacy_VerifyProof(h hash.Hash, merkleRoot []byte, proofSet [][]byte, proofIndex uint64, numLeaves uint64) bool {
	if merkleRoot == nil {
		return false
	}
	if proofIndex >= numLeaves {
		return false
	}

	height := 0
	if len(proofSet) <= height {
		return false
	}
	sum := leafSum(h, proofSet[height])

	height++

	stableEnd := proofIndex
	for {
		subTreeStartIndex := (proofIndex / (1 << uint(height))) * (1 << uint(height)) // round down to the nearest 1 << height
		subTreeEndIndex := subTreeStartIndex + (1 << (uint(height))) - 1              // subtract 1 because the start index is inclusive
		if subTreeEndIndex >= numLeaves {
			break
		}
		stableEnd = subTreeEndIndex

		if len(proofSet) <= height {
			return false
		}
		if proofIndex-subTreeStartIndex < 1<<uint(height-1) {
			sum = nodeSum(h, sum, proofSet[height])
		} else {
			sum = nodeSum(h, proofSet[height], sum)
		}
		height++
	}

	if stableEnd != numLeaves-1 {
		if len(proofSet) <= height {
			return false
		}
		sum = nodeSum(h, sum, proofSet[height])
		height++
	}
	for height < len(proofSet) {
		sum = nodeSum(h, proofSet[height], sum)
		height++
	}

	return bytes.Equal(sum, merkleRoot)
}
