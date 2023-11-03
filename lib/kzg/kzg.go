package kzg

import (
	"fmt"
	"math/big"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/kzg"
)

const (
	ShardingLen = 31
	MaxShards   = 1024
	MaxFileSize = MaxShards * ShardingLen
)

type G1 = bls12377.G1Affine
type G2 = bls12377.G2Affine
type GT = bls12377.GT
type Fr = fr.Element

type Proof = kzg.OpeningProof

// ProvingKey used to create or open commitments
type ProvingKey struct {
	G1 []bls12377.G1Affine // [G₁ [α]G₁ , [α²]G₁, ... ]
}

// VerifyingKey used to verify opening proofs
type VerifyingKey struct {
	G2 [2]bls12377.G2Affine // [G₂, [α]G₂ ]
	G1 bls12377.G1Affine
}

type PublicKey struct {
	*kzg.SRS
}

func GenKey() (*PublicKey, error) {
	alpha := big.NewInt(12345678)
	kzgSRS, err := kzg.NewSRS(uint64(MaxShards*4), alpha)
	if err != nil {
		return nil, err
	}

	return &PublicKey{
		SRS: kzgSRS,
	}, nil
}

func (pk *PublicKey) Commitment(d []byte) (G1, error) {
	if len(d) > MaxFileSize {
		return G1{}, fmt.Errorf("data size too large")
	}

	shards := Split(d)

	return kzg.Commit(shards, pk.SRS.Pk)
}

func (pk *PublicKey) Open(rnd Fr, d []byte) (Proof, error) {
	if len(d) > MaxFileSize {
		return Proof{}, fmt.Errorf("data size too large")
	}

	shards := Split(d)
	return kzg.Open(shards, rnd, pk.SRS.Pk)
}

func (pk *PublicKey) Verify(rnd Fr, commit G1, pf Proof) error {
	return kzg.Verify(&commit, &pf, rnd, pk.SRS.Vk)
}
