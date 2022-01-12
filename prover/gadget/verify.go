package gadget

import (
	"fmt"

	"github.com/AlexandreBelling/gnark/notinternal/backend/bn254/witness"
	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Verify verifies a proof with given VerifyingKey and publicWitness
func Verify(proof *Proof, vk *VerifyingKey, publicWitness witness.Witness) error {

	// Readd the public randomness in there
	publicWitness = append([]fr.Element{proof.InitialRandomness}, publicWitness...)

	// Takes a subslice and convert to fr.Element
	subSlice := func(array []fr.Element, indices []int, offset int) []fr.Element {
		res := make([]fr.Element, len(indices))
		for i, idx := range indices {
			res[i] = array[idx+offset]
			res[i].FromMont()
		}
		return res
	}

	// Separate Gkrs / not Gkrs
	pubVarGkr := subSlice(publicWitness, vk.pubGkrVarID, 0)
	pubVarNotGkr := subSlice(publicWitness, vk.pubNotGkrVarID, -1) // -1 for the public input

	// The initial randomness should have been passes by the prover as part of the public witness
	common.Assert(proof.InitialRandomness != fr.NewElement(0), "The initial randomness should be known at this point")

	// Computes separately the priv/pub GKRs
	var KrsGkr, KrsPub, KrsGkrPub bn254.G1Affine
	KrsGkrPub.MultiExp(vk.pubKGkr, pubVarGkr, ecc.MultiExpConfig{})
	KrsGkr.Add(&KrsGkrPub, &proof.KrsGkrPriv)

	// Check the initial randomness
	initialRandomness := DeriveRandomnessFromPoint(KrsGkr)
	if initialRandomness != proof.InitialRandomness {
		return fmt.Errorf(
			"The initial randomness is incorrect. Provided %v != recovered %v",
			pubVarNotGkr[0].String(),
			initialRandomness.String(),
		)
	}

	// Processes the Krs pub
	// 1) Non-Gkr stuffs
	KrsPub.MultiExp(vk.pubKNotGkr[1:], pubVarNotGkr, ecc.MultiExpConfig{})
	// 2) Complete with the GKR stuffs and the constant "1"
	KrsPub.Add(&KrsPub, &KrsGkrPub)
	KrsPub.Add(&KrsPub, &vk.pubKNotGkr[0])

	// Run the pairing-checks
	right, err := bn254.Pair(
		[]bn254.G1Affine{KrsPub, proof.Krs, proof.KrsGkrPriv, proof.Ar},
		[]bn254.G2Affine{vk.vk.G2.GammaNeg, vk.vk.G2.DeltaNeg, vk.deltaSigmaInvNeg, proof.Bs},
	)

	if err != nil {
		return fmt.Errorf("Error in the miller loop %v", err)
	}

	if !vk.vk.E.Equal(&right) {
		return fmt.Errorf("The pairing failed")
	}

	return nil

}
