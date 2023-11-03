package kzg

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/fields_bls12377"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
)

// Digest commitment of a polynomial.
type Digest = sw_bls12377.G1Affine

// VK verification key (G2 part of SRS)
type VK struct {
	G1 sw_bls12377.G1Affine    // G₁
	G2 [2]sw_bls12377.G2Affine // [G₂, [α]G₂]
}

// OpeningProof KZG proof for opening at a single point.
type OpeningProof struct {
	// H quotient polynomial (f - f(z))/(x-z)
	H sw_bls12377.G1Affine

	// ClaimedValue purported value
	ClaimedValue frontend.Variable
}

// Verify verifies a KZG opening proof at a single point
func Verify(api frontend.API, commitment Digest, proof OpeningProof, point frontend.Variable, srs VK) {
	// [f(s) - f(r)]G₁
	var claimedValueG1Aff sw_bls12377.G1Affine
	claimedValueG1Aff.ScalarMul(api, srs.G1, proof.ClaimedValue).
		Neg(api, claimedValueG1Aff).
		AddAssign(api, commitment)

	// [r*H(r)]G₁
	var rH sw_bls12377.G1Affine
	rH.ScalarMul(api, proof.H, point)
	claimedValueG1Aff.AddAssign(api, rH)

	// [-H(r)]G₁
	var negH sw_bls12377.G1Affine
	negH.Neg(api, proof.H)

	// e([f(α) - f(a)]G₁, G₂).e([-H(α)]G₁, [α-a]G₂) ==? 1
	resPairing, _ := sw_bls12377.Pair(
		api,
		[]sw_bls12377.G1Affine{claimedValueG1Aff, negH},
		[]sw_bls12377.G2Affine{srs.G2[0], srs.G2[1]},
	)

	var one fields_bls12377.E12
	one.SetOne()
	resPairing.AssertIsEqual(api, one)

}
