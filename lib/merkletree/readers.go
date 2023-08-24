package merkletree

import (
	"errors"
	"hash"
	"io"
)

func (t *ProofTree) ReadAll(r io.Reader, segmentSize int) error {
	for {
		segment := make([]byte, segmentSize)
		n, readErr := io.ReadFull(r, segment)
		if readErr == io.EOF {
			// All data has been read.
			break
		} else if readErr == io.ErrUnexpectedEOF {
			// This is the last segment, and there aren't enough bytes to fill
			// the entire segment. Note that the next call will return io.EOF.
			segment = segment[:n]
		} else if readErr != nil {
			return readErr
		}
		t.Push(segment)
	}
	return nil
}

func ReaderRoot(r io.Reader, h hash.Hash, segmentSize int) (root []byte, err error) {
	tree := New(h)
	err = tree.ReadAll(r, segmentSize)
	if err != nil {
		return
	}
	root = tree.Root()
	return
}

func BuildReaderProof(r io.Reader, h hash.Hash, segmentSize int, index uint64) (root []byte, proofSet [][]byte, numLeaves uint64, err error) {
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
	root, proofSet, _, numLeaves = tree.Prove()
	if len(proofSet) == 0 {
		err = errors.New("index was not reached while creating proof")
		return
	}
	return
}
