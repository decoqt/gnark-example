// Original Copyright (c) 2015 Nebulous
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package merkletree

import (
	"bytes"
	"hash"
)

func VerifyProof(h hash.Hash, merkleRoot []byte, proofSet [][]byte, proofIndex uint64) bool {
	if len(proofSet) == 0 {
		return false
	}
	sum := leafSum(h, proofSet[0])
	for i := 1; i < len(proofSet); i++ {
		po := (proofIndex & (1 << (i - 1))) >> (i - 1)
		if po == 1 {
			sum = nodeSum(h, proofSet[i], sum)
		} else {
			sum = nodeSum(h, sum, proofSet[i])
		}
	}

	return bytes.Equal(sum, merkleRoot)
}
