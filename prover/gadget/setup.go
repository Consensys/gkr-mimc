package gadget

import (
	"fmt"
	"math/big"

	grothBack "github.com/AlexandreBelling/gnark/backend/groth16"
	"github.com/AlexandreBelling/gnark/frontend"
	"github.com/AlexandreBelling/gnark/notinternal/backend/bn254/groth16"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func init() {
	Setup = wrapSetupFunc(grothBack.Setup)
	DummySetup = wrapSetupFunc(groth16DummySetup)
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

func wrapSetupFunc(innerF innerSetupFunc) outerSetupFunc {
	return func(r1cs *R1CS) (ProvingKey, VerifyingKey, error) {
		// Runs the groth16 setup

		fmt.Printf("gnark dummy setup \n")
		pk, vk, err := innerF(&r1cs.r1cs)
		if err != nil {
			return ProvingKey{}, VerifyingKey{}, err
		}

		fmt.Printf("preinite public params \n")
		pkRes, vkRes := PreInitializePublicParams(pk, vk)
		fmt.Printf("subslice public params \n")
		SubSlicesPublicParams(r1cs, &pkRes, &vkRes)
		fmt.Printf("mark with sigma \n")
		MarkWithSigma(&pkRes, &vkRes)
		fmt.Printf("erase old k \n")
		EraseOldK(&pkRes, &vkRes)

		// Injects the proving key inside the R1CS
		r1cs.provingKey = &pkRes

		return pkRes, vkRes, err
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

// Setup then wrap the keys
func PreInitializePublicParams(pk grothBack.ProvingKey, vk grothBack.VerifyingKey) (ProvingKey, VerifyingKey) {
	pkType := pk.(*groth16.ProvingKey)
	vkType := vk.(*groth16.VerifyingKey)

	pkRes := ProvingKey{
		pk: *pkType,
	}

	vkRes := VerifyingKey{
		vk: *vkType,
	}

	return pkRes, vkRes
}

func SubSlicesPublicParams(r1cs *R1CS, pk *ProvingKey, vk *VerifyingKey) {
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
	privGkrSigma := subSlice(pk.pk.G1.K, r1cs.privGkrVarID, -vk.vk.NbPublicWitness()-1)
	privKNotGkr := subSlice(pk.pk.G1.K, r1cs.privNotGkrVarID, -vk.vk.NbPublicWitness()-1)
	pubKNotGkr := append([]bn254.G1Affine{vk.vk.G1.K[0]}, subSlice(vk.vk.G1.K, r1cs.pubNotGkrVarID, 0)...)
	pubKGkr := subSlice(vk.vk.G1.K, r1cs.pubGkrVarID, 0)

	// Passes the subslices arrays
	pk.privKGkrSigma = privGkrSigma
	pk.privKNotGkr = privKNotGkr
	vk.pubKGkr = pubKGkr
	vk.pubKNotGkr = pubKNotGkr

	// Passes also the subslices indexes
	vk.pubGkrVarID = r1cs.pubGkrVarID
	vk.pubNotGkrVarID = r1cs.pubNotGkrVarID
}

func MarkWithSigma(pk *ProvingKey, vk *VerifyingKey) {

	// Sigma and its inverse are toxic wastes
	var sigma, sigmaInv fr.Element
	var sigmaBI, sigmaInvBI big.Int
	sigma.SetRandom()
	sigmaInv.Inverse(&sigma)
	sigma.ToBigIntRegular(&sigmaBI)
	sigmaInv.ToBigIntRegular(&sigmaInvBI)

	// Marks the privGkrK with sigma so that we can
	// forcefully isolate this part in a pairing
	for i := range pk.privKGkrSigma {
		pk.privKGkrSigma[i].ScalarMultiplication(&pk.privKGkrSigma[i], &sigmaBI)
	}

	// Also marks deltaNeg in the verification key
	vk.deltaSigmaInvNeg.ScalarMultiplication(&vk.vk.G2.DeltaNeg, &sigmaInvBI)
}

func EraseOldK(pk *ProvingKey, vk *VerifyingKey) {
	pk.pk.G1.K = []bn254.G1Affine{}
	vk.vk.G1.K = []bn254.G1Affine{}
}
