package gadget

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/notinternal/backend/bn254/groth16"
)

// Extend proof for GKR-enabled SNARK
type Proof struct {
	groth16.Proof
	KSumXiBar      bn254.G1Affine
	KSumAlphaXiBar bn254.G1Affine
}

type ProvingKey struct {
	groth16.ProvingKey
}
