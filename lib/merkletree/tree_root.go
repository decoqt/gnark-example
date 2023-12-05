package merkletree

import (
	"hash"
)

// only calculate root
type RTree struct {
	roots        []*heightRoot
	hash         hash.Hash
	currentIndex uint64
}

type heightRoot struct {
	status bool // false means no data; true means has data
	sum    []byte
}

func NewRTree(h hash.Hash) *RTree {
	rt := &RTree{
		hash:  h,
		roots: make([]*heightRoot, 0, 1),
	}
	rt.roots = append(rt.roots, new(heightRoot))
	return rt
}

func (rt *RTree) Push(data []byte) {
	sum := leafSum(rt.hash, data)
	for i := 0; i < len(rt.roots); i++ {
		if rt.roots[i].status {
			// need one more height
			if i == len(rt.roots)-1 {
				rt.roots = append(rt.roots, new(heightRoot))
			}
			// clear current and cache for next
			sum = nodeSum(rt.hash, rt.roots[i].sum, sum)
			rt.roots[i].status = false
		} else {
			rt.roots[i].sum = sum
			rt.roots[i].status = true
			break
		}
	}

	rt.currentIndex++
}

func (rt *RTree) Root() []byte {
	var root []byte
	for i := 0; i < len(rt.roots); i++ {
		if rt.roots[i].status {
			if len(root) != 0 {
				root = nodeSum(rt.hash, rt.roots[i].sum, root)
			} else {
				if i < len(rt.roots)-1 {
					root = nodeSum(rt.hash, rt.roots[i].sum, rt.roots[i].sum)
				} else {
					// top one
					root = rt.roots[i].sum
				}
			}
		} else {
			if len(root) != 0 {
				root = nodeSum(rt.hash, root, root)
			}
		}
	}

	return root
}
