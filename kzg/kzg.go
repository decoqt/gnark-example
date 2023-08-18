package main

import (
	"fmt"
	"math/big"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/kzg"
)

const (
	ShardingLen = 127
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
	SRS *kzg.SRS
	Pk  ProvingKey
	Vk  VerifyingKey
}

func GenKey() (*PublicKey, error) {
	alpha := big.NewInt(12345678)
	kzgSRS, err := kzg.NewSRS(uint64(MaxShards*4), alpha)
	if err != nil {
		return nil, err
	}
	pk := ProvingKey{
		G1: kzgSRS.G1,
	}
	vk := VerifyingKey{
		G1: kzgSRS.G1[0],
		G2: kzgSRS.G2,
	}

	return &PublicKey{
		SRS: kzgSRS,
		Pk:  pk,
		Vk:  vk,
	}, nil
}

func (pk *PublicKey) Commitment(d []byte) (G1, error) {
	if len(d) > MaxFileSize {
		return G1{}, fmt.Errorf("data size too large")
	}

	shards := split(d)

	return kzg.Commit(shards, pk.SRS)
}

func (pk *PublicKey) Open(rnd Fr, d []byte) (Proof, error) {
	if len(d) > MaxFileSize {
		return Proof{}, fmt.Errorf("data size too large")
	}

	shards := split(d)
	return kzg.Open(shards, rnd, pk.SRS)
}

func (pk *PublicKey) Verify(rnd Fr, commit G1, pf Proof) error {
	return kzg.Verify(&commit, &pf, rnd, pk.SRS)
}
