package groth16

import (
	"math/big"

	"github.com/consensys/gkr-mimc/prover/backend/bn254/cs"
	"github.com/consensys/gkr-mimc/prover/backend/bn254/groth16"
	gnarkGroth16 "github.com/consensys/gkr-mimc/prover/backend/bn254/groth16"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Wrapper around R1CS + the information for the layer 2 of the compiler
type GkrR1CS struct {
	Groth16 cs.R1CS
	Xis     []int // Position of the variables to be excluded from the public inputs
}

// Wrapper around the proving key + The Additional setup for `T`
type ProvingKey struct {
	Groth16 gnarkGroth16.ProvingKey
	G1      struct {
		KAlphaXi []curve.G1Affine // The indexes corresponds to the xis
		KXiBar   []curve.G1Affine
	}
}

// Wrapper around the verifying key + The Additional setup for `T`
type VerifyingKey struct {
	Groth16 gnarkGroth16.VerifyingKey
	G2      struct {
		GammaAlpha curve.G2Affine
	}
	G1 struct {
		KXi []curve.G1Affine
	}
}

// Setup of the variant of Groth16
func Setup(r1cs *GkrR1CS, pk *ProvingKey, vk *VerifyingKey) error {
	// Performs the groth16 setup
	if err := groth16.Setup(&r1cs.Groth16, &pk.Groth16, &vk.Groth16); err == nil {
		return err
	}

	// TOXIC WASTE: Trusted setup for the alpha
	var alpha fr.Element
	alpha.SetRandom()
	var alphaBI big.Int

	// Enrich the verification key
	vk.G2.GammaAlpha.ScalarMultiplication(&vk.Groth16.G2.Gamma, alpha.ToBigInt(&alphaBI))

	// Enrich the proving key, creates the kAlphaXi in the proving key
	pk.G1.KAlphaXi = make([]curve.G1Affine, len(r1cs.Xis))
	for i, xi := range r1cs.Xis {
		pk.G1.KAlphaXi[i].ScalarMultiplication(
			&vk.Groth16.G1.K[xi+1], &alphaBI,
		)
	}

	// Enrich the verification key, creates the KXi and remove the K

	return nil
}
