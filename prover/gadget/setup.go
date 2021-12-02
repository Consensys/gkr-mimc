package gadget

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	groth16Back "github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/notinternal/backend/bn254/groth16"
)

// Wrappers around the proving key
type ProvingKey struct {
	pk                                  groth16.ProvingKey
	privKNotGkr, pubKGkr, privKGkrSigma []bn254.G1Affine
}

// Wrapper around the verifying key
type VerifyingKey struct {
	vk                  groth16.VerifyingKey
	deltaSigmaInvNeg    bn254.G2Affine
	pubKNotGkr, pubKGkr []bn254.G1Affine
}

// Wraps the setup of gnark
func Setup(r1cs R1CS) (ProvingKey, VerifyingKey, error) {

	// Runs the groth16 setup
	pk, vk, err := groth16Back.Setup(&r1cs.r1cs)
	if err != nil {
		return ProvingKey{}, VerifyingKey{}, err
	}

	// Sigma and its inverse are toxic wastes
	var sigma, sigmaInv fr.Element
	var sigmaBI, sigmaInvBI *big.Int
	sigma.SetRandom()
	sigmaInv.Inverse(&sigma)
	sigma.ToBigInt(sigmaBI)
	sigmaInv.ToBigInt(sigmaInvBI)

	pkType := pk.(*groth16.ProvingKey)
	vkType := vk.(*groth16.VerifyingKey)

	// Subslices a slice and returns the element in the order of subIndices
	// offset allows to take (array[index + offset])
	subSlice := func(array []bn254.G1Affine, subIndices []int, offset int) []bn254.G1Affine {
		res := make([]bn254.G1Affine, len(subIndices))
		for _, idx := range subIndices {
			res = append(res, array[idx+offset])
		}
		return res
	}

	// Marks the privGkrSigma with a sigma to prevent malicious users
	// to mix it with non-GKR inputs
	privGkrSigma := subSlice(pkType.G1.K, r1cs.privGkrVarID, -vk.NbPublicWitness())
	for i := range privGkrSigma {
		privGkrSigma[i].ScalarMultiplication(&privGkrSigma[i], sigmaBI)
	}

	// Also marks deltaNeg in the verification key
	var deltaSigmaInvNeg bn254.G2Affine
	deltaSigmaInvNeg.ScalarMultiplication(&vkType.G2.Delta, sigmaInvBI)

	pkRes := ProvingKey{
		pk:            *pkType,
		privKGkrSigma: privGkrSigma,
		privKNotGkr:   subSlice(pkType.G1.K, r1cs.privNotGkrVarID, -vk.NbPublicWitness()),
		pubKGkr:       subSlice(vkType.G1.K, r1cs.pubGkrVarID, 1),
	}

	vkRes := VerifyingKey{
		vk:               *vkType,
		deltaSigmaInvNeg: deltaSigmaInvNeg,
		pubKGkr:          pkRes.pubKGkr,
		pubKNotGkr:       subSlice(vkType.G1.K, r1cs.pubNotGkrVarID, 1),
	}

	// Shoots the original K part of the proving key
	pkRes.pk.G1.K = []bn254.G1Affine{}
	vkRes.vk.G1.K = []bn254.G1Affine{}

	return pkRes, vkRes, nil
}
