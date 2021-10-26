package groth16

import (
	"fmt"

	"github.com/consensys/gkr-mimc/prover/backend/bn254/witness"
	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
)

func Verify(vk *VerifyingKey, proof *Proof, witness witness.Witness) (bool, error) {
	// Pairing check for the knowledge of T
	valid, err := VerifyT(vk, proof)
	if !valid || err != nil {
		return false, err
	}

	// Run U0 on the remaining public inputs
	kSumXi, err := U(vk, witness)
	if err != nil {
		return false, err
	}

	// Recover the full kSum
	var kSum curve.G1Affine
	kSum.Add(kSumXi, &proof.KSumXiBar)

	// Run the final part of the groth16 verification
	return V(vk, proof, &kSum)
}

// Check the argument of knowledge T of the "hidden public inputs"
func VerifyT(vk *VerifyingKey, proof *Proof) (bool, error) {
	return curve.PairingCheck(
		[]curve.G1Affine{proof.T, proof.KSumXiBar},
		[]curve.G2Affine{vk.Groth16.G2.GammaNeg, vk.G2.GammaAlpha},
	)
}

// Public inputs contribution of the verifier
func U(vk *VerifyingKey, witness witness.Witness) (*curve.G1Affine, error) {
	if len(witness) != (len(vk.Groth16.G1.K) - 1) {
		return nil, fmt.Errorf("invalid witness size, got %d, expected %d (public - ONE_WIRE)", len(witness), len(vk.Groth16.G1.K)-1)
	}

	// compute e(Σx.[Kvk(t)]1, -[γ]2)
	var kSum curve.G1Jac
	if _, err := kSum.MultiExp(vk.G1.KXi, witness, ecc.MultiExpConfig{ScalarsMont: true}); err != nil {
		return nil, err
	}
	kSum.AddMixed(&vk.Groth16.G1.K[0])
	var kSumAff curve.G1Affine
	kSumAff.FromJacobian(&kSum)

	return &kSumAff, nil
}

// Proof contribution of the verifier : simplified compared to gnark's groth16
// (in case we want to maintain some of it)
func V(vk *VerifyingKey, proof *Proof, kSumAff *curve.G1Affine) (bool, error) {

	// compute (eKrsδ, eArBs)
	actualE, err := curve.Pair(
		[]curve.G1Affine{*kSumAff, proof.Groth16.Krs, proof.Groth16.Ar},
		[]curve.G2Affine{vk.Groth16.G2.GammaNeg, vk.Groth16.G2.DeltaNeg, proof.Groth16.Bs},
	)

	// wait for (eKrsδ, eArBs)
	if err != nil {
		return false, err
	}

	if !vk.Groth16.E.Equal(&actualE) {
		return false, fmt.Errorf("Failed pairing check")
	}
	return true, nil
}
