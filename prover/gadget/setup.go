package gadget

import (
	"math/big"

	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	grothBack "github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/notinternal/backend/bn254/groth16"
)

func init() {
	Setup = wrapsSetupFunc(grothBack.Setup)
	DummySetup = wrapsSetupFunc(groth16DummySetup)
}

// The setup and dummy setups are initialized by applying our wrapper
var Setup outerSetupFunc
var DummySetup outerSetupFunc

// inner function type to capture both Setup and DummySetup
type innerSetupFunc func(frontend.CompiledConstraintSystem) (grothBack.ProvingKey, grothBack.VerifyingKey, error)

// outer setup function type
type outerSetupFunc func(*R1CS) (ProvingKey, VerifyingKey, error)

// Wrappers around the proving key
type ProvingKey struct {
	pk                                  groth16.ProvingKey
	privKNotGkr, pubKGkr, privKGkrSigma []bn254.G1Affine
}

// Wrapper around the verifying key
type VerifyingKey struct {
	vk                          groth16.VerifyingKey
	deltaSigmaInvNeg            bn254.G2Affine
	pubKNotGkr, pubKGkr         []bn254.G1Affine
	pubGkrVarID, pubNotGkrVarID []int
}

// Wraps the setup of gnark to create a GKR setup func
func wrapsSetupFunc(innerF innerSetupFunc) outerSetupFunc {

	return func(r1cs *R1CS) (ProvingKey, VerifyingKey, error) {

		// Runs the groth16 setup
		pk, vk, err := innerF(&r1cs.r1cs)
		if err != nil {
			return ProvingKey{}, VerifyingKey{}, err
		}

		// Sigma and its inverse are toxic wastes
		var sigma, sigmaInv fr.Element
		var sigmaBI, sigmaInvBI big.Int
		sigma.SetRandom()
		sigmaInv.Inverse(&sigma)
		sigma.ToBigIntRegular(&sigmaBI)
		sigmaInv.ToBigIntRegular(&sigmaInvBI)

		pkType := pk.(*groth16.ProvingKey)
		vkType := vk.(*groth16.VerifyingKey)

		// Subslices a slice and returns the element in the order of subIndices
		// offset allows to take (array[index + offset])
		subSlice := func(array []bn254.G1Affine, subIndices []int, offset int) []bn254.G1Affine {
			res := make([]bn254.G1Affine, 0, len(subIndices))
			for _, idx := range subIndices {
				res = append(res, array[idx+offset])
			}
			return res
		}

		// Marks the privGkrSigma with a sigma to prevent malicious users
		// to mix it with non-GKR inputs
		privGkrSigma := subSlice(pkType.G1.K, r1cs.privGkrVarID, -vk.NbPublicWitness()-1)
		privKNotGkr := subSlice(pkType.G1.K, r1cs.privNotGkrVarID, -vk.NbPublicWitness()-1)
		common.Assert(privGkrSigma[0] == pkType.G1.K[0], "Misalignement")

		// Test that the splitting of the group element is bijective
		{
			var krsSplitted, krs0 bn254.G1Affine
			for _, g := range privGkrSigma {
				krsSplitted.Add(&krsSplitted, &g)
			}

			for _, g := range privKNotGkr {
				krsSplitted.Add(&krsSplitted, &g)
			}

			for _, g := range pkType.G1.K {
				krs0.Add(&krs0, &g)
			}

			common.Assert(krs0 == krsSplitted, "%v != %v \n", krs0.String(), krsSplitted.String())
		}

		// Marks the privGkrK with sigma so that we can
		// forcefully isolate this part in a pairing
		for i := range privGkrSigma {
			privGkrSigma[i].ScalarMultiplication(&privGkrSigma[i], &sigmaBI)
		}

		// Also marks deltaNeg in the verification key
		var deltaSigmaInvNeg bn254.G2Affine
		deltaSigmaInvNeg.ScalarMultiplication(&vkType.G2.DeltaNeg, &sigmaInvBI)

		pkRes := ProvingKey{
			pk:            *pkType,
			privKGkrSigma: privGkrSigma,
			// Minus one is for taking the "constant wire" into account
			privKNotGkr: privKNotGkr,
			pubKGkr:     subSlice(vkType.G1.K, r1cs.pubGkrVarID, 0),
		}

		vkRes := VerifyingKey{
			vk:               *vkType,
			deltaSigmaInvNeg: deltaSigmaInvNeg,
			pubKGkr:          pkRes.pubKGkr,
			pubGkrVarID:      r1cs.pubGkrVarID,
			pubKNotGkr:       append([]bn254.G1Affine{vkType.G1.K[0]}, subSlice(vkType.G1.K, r1cs.pubNotGkrVarID, 0)...),
			pubNotGkrVarID:   r1cs.pubNotGkrVarID,
		}

		// For debugging only : we split the proving key but we should still have that
		{
			var krsSumPKGroth16, krsSumGkr, krsSumNotGkr bn254.G1Affine
			for _, k := range pkType.G1.K {
				krsSumPKGroth16.Add(&krsSumPKGroth16, &k)
			}

			for _, k := range privGkrSigma {
				krsSumGkr.Add(&krsSumGkr, &k)
			}

			for _, k := range pkRes.privKNotGkr {
				krsSumNotGkr.Add(&krsSumNotGkr, &k)
			}

			left, err := bn254.Pair([]bn254.G1Affine{krsSumPKGroth16}, []bn254.G2Affine{vkType.G2.DeltaNeg})
			common.Assert(err == nil, "Error during the pairing")

			right, err := bn254.Pair(
				[]bn254.G1Affine{krsSumNotGkr, krsSumGkr},
				[]bn254.G2Affine{vkType.G2.DeltaNeg, vkRes.deltaSigmaInvNeg},
			)

			common.Assert(left == right, "%v != %v", left.String(), right.String())
		}

		// Shoots the original K part of the proving key
		// To save space
		pkRes.pk.G1.K = []bn254.G1Affine{}
		vkRes.vk.G1.K = []bn254.G1Affine{}

		// Injects the proving key inside the R1CS
		r1cs.provingKey = &pkRes

		return pkRes, vkRes, nil

	}
}

// Wraps the groth16's dummy setup so it also returns a verification key
func groth16DummySetup(r1cs frontend.CompiledConstraintSystem) (grothBack.ProvingKey, grothBack.VerifyingKey, error) {
	pk, err := grothBack.DummySetup(r1cs)
	_, _, pub := r1cs.GetNbVariables()

	_, _, _, g2 := bn254.Generators()

	// Creates an empty verifying key
	vk := groth16.VerifyingKey{}
	vk.G1.K = make([]bn254.G1Affine, pub)

	// In order to not trivialise our test we also set deltaNeg to a random point
	var rng big.Int
	var rngFr fr.Element
	rngFr.SetRandom()
	rngFr.ToBigIntRegular(&rng)
	vk.G2.DeltaNeg.ScalarMultiplication(&g2, &rng)

	return pk, &vk, err
}
