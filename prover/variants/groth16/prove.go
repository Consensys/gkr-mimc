package groth16

import (
	"github.com/consensys/gkr-mimc/prover/backend/bn254/groth16"
	"github.com/consensys/gkr-mimc/prover/backend/bn254/witness"
	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
)

// Proof wraps the groth16 prove with our compiler
type Proof struct {
	Groth16   groth16.Proof
	T         curve.G1Affine // Proves the knowledge of exponents for the Xis
	KSumXiBar curve.G1Affine
}

// Prove wraps the groth16 prover with our compiler
func Prove(r1cs *GkrR1CS, pk *ProvingKey, witness witness.Witness, opt backend.ProverOption) (*Proof, error) {
	// Call the Groth16 prover
	proof, err := groth16.Prove(&r1cs.Groth16, &pk.Groth16, witness, opt)
	if err != nil {
		return nil, err
	}

	// Collect the public inputs in a single vector before performing the multiexponentiation
	privGkrio := make([]fr.Element, len(pk.G1.KAlphaXi))
	for i, xi := range r1cs.Xis {
		privGkrio[i] = witness[xi]
	}

	var t, kSumXiBar curve.G1Affine
	t.MultiExp(pk.G1.KAlphaXi, privGkrio, ecc.MultiExpConfig{})
	kSumXiBar.MultiExp(pk.G1.KXiBar, privGkrio, ecc.MultiExpConfig{})

	return &Proof{
		Groth16:   *proof,
		T:         t,
		KSumXiBar: kSumXiBar,
	}, nil
}
