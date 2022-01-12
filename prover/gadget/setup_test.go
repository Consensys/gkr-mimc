package gadget

import (
	"testing"

	"github.com/AlexandreBelling/gnarkbackend/groth16"
	"github.com/consensys/gkr-mimc/hash"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/assert"
)

func TestActualSetup(t *testing.T) {
	setupTestGen(t, groth16.Setup)
}

func TestDummySetup(t *testing.T) {
	setupTestGen(t, groth16DummySetup)
}

func setupTestGen(t *testing.T, fun innerSetupFunc) {
	n := 10
	preimages := make([]fr.Element, n)
	hashes := make([]fr.Element, n)

	for i := range preimages {
		preimages[i].SetUint64(uint64(i))
		hash.MimcUpdateInplace(&hashes[i], preimages[i])
	}

	innerCircuit := AllocateTestGadgetCircuit(n)
	circuit := WrapCircuitUsingGkr(&innerCircuit, WithChunkSize(16), WithNCore(1))

	r1cs, err := circuit.Compile()
	assert.NoError(t, err)
	assert.Equal(t, len(r1cs.pubNotGkrVarID), 1) // One for the initial randomness

	_, _, pub := r1cs.r1cs.GetNbVariables()
	assert.Equal(t, pub, 2) // One for the initial randomness + 1 for the constant = 1

	// We need to at least run the dummy setup so that the solver knows what to do
	// So that the proving key can attach itself to the R1CS
	initialPk, initialVk, err := fun(&r1cs.r1cs)
	pk, vk := PreInitializePublicParams(initialPk, initialVk)
	SubSlicesPublicParams(&r1cs, &pk, &vk)

	assert.Equal(t, pk.privKGkrSigma[0], pk.pk.G1.K[0], "Misalignement")

	{ // Tests that the subslicing works as intended
		var krsSplitted, krs0 bn254.G1Affine
		for _, g := range pk.privKGkrSigma {
			krsSplitted.Add(&krsSplitted, &g)
		}

		for _, g := range pk.privKNotGkr {
			krsSplitted.Add(&krsSplitted, &g)
		}

		for _, g := range pk.pk.G1.K {
			krs0.Add(&krs0, &g)
		}

		assert.Equal(t, krs0, krsSplitted)
	}

	MarkWithSigma(&pk, &vk)

	// For debugging only : we split the proving key but we should still have that
	{
		var krsSumPKGroth16, krsSumGkr, krsSumNotGkr bn254.G1Affine
		for _, k := range pk.pk.G1.K {
			krsSumPKGroth16.Add(&krsSumPKGroth16, &k)
		}

		for _, k := range pk.privKGkrSigma {
			krsSumGkr.Add(&krsSumGkr, &k)
		}

		for _, k := range pk.privKNotGkr {
			krsSumNotGkr.Add(&krsSumNotGkr, &k)
		}

		left, err := bn254.Pair([]bn254.G1Affine{krsSumPKGroth16}, []bn254.G2Affine{vk.vk.G2.DeltaNeg})
		assert.NoError(t, err, "Error during the pairing")

		right, err := bn254.Pair(
			[]bn254.G1Affine{krsSumNotGkr, krsSumGkr},
			[]bn254.G2Affine{vk.vk.G2.DeltaNeg, vk.deltaSigmaInvNeg},
		)

		assert.Equal(t, left, right, "%v != %v", left.String(), right.String())
	}

}
