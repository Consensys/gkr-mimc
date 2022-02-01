package examples

import (
	"github.com/consensys/gkr-mimc/circuit"
	"github.com/consensys/gkr-mimc/circuit/gates"
	"github.com/consensys/gkr-mimc/hash"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Evaluator for all layers except the last
func evalMimc(i int) circuit.Evaluator {
	return func(inps []fr.Element) []fr.Element {
		mid := len(inps) / 2
		res := make([]fr.Element, len(inps))
		var tmp fr.Element
		for h := 0; h < mid; h++ {
			// perform the cipher operation
			tmp.Add(&inps[h], &hash.Arks[i])
			res[h].
				Square(&tmp).
				Mul(&res[h], &tmp).
				Square(&res[h]).
				Mul(&tmp, &res[h]).
				Add(&res[h], &inps[h+mid])
		}
		// Perform the full copy at once
		copy(res[mid:], inps[mid:])
		return res
	}
}

func evalLastLayer(i int) circuit.Evaluator {
	return func(inps []fr.Element) []fr.Element {
		mid := len(inps) / 2
		res := make([]fr.Element, mid)
		var tmp fr.Element
		for h := 0; h < mid; h++ {
			// perform the cipher operation
			tmp.Add(&inps[h], &hash.Arks[i])
			res[h].
				Square(&tmp).
				Mul(&res[h], &tmp).
				Square(&res[h]).
				Mul(&tmp, &res[h]).
				Add(&res[h], &inps[h+mid])
		}
		return res
	}
}

// CreateMimcCircuit returns the GKR MIMC proving circuit
func CreateMimcCircuit() circuit.Circuit {
	nRounds := 91
	wiring := make([][]circuit.Wire, nRounds)

	for i := 0; i < nRounds-1; i++ {
		wiring[i] = []circuit.Wire{
			{L: 1, R: 0, O: 0, Gate: gates.NewCipherGate(hash.Arks[i])},
			{L: 1, R: 0, O: 1, Gate: gates.CopyGate{}},
		}
	}

	// And we don't copy the input in the last layer
	wiring[nRounds-1] = []circuit.Wire{
		{L: 1, R: 0, O: 0, Gate: gates.NewCipherGate(hash.Arks[nRounds-1])},
	}

	res := circuit.NewCircuit(wiring)

	for i := 0; i < nRounds-1; i++ {
		res.Layers[i].CustomEvaluator = evalMimc(i)
	}

	res.Layers[nRounds-1].CustomEvaluator = evalLastLayer(nRounds - 1)

	return res
}
