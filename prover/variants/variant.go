package variant

import "github.com/consensys/gnark-crypto/ecc/bn254"

type Proof struct {
	G1 struct {
		KSumXiBar bn254.G1Affine
	}
}

type ProvingKey struct {
	G1 struct {
		KAlphaXi []bn254.G1Affine
	}
}
