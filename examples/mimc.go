package examples

import (
	"gkr-mimc/gkr"
	"gkr-mimc/hash"
	"gkr-mimc/sumcheck"

	"github.com/consensys/gurvy/bn256/fr"
)

// The Mimc layers are shaped
//   s, x -> (s + c)^7+ x, x

func copyTableGeneratorMimc(q []fr.Element) sumcheck.BookKeepingTable {
	// copy(q, hR, hL) = 1 iff (q, hR, hL) == (1, 1, 0)
	// After we fold it on q, the table holds the values (0 0 1-q 0)
	table := make([]fr.Element, 4)
	table[2].Set(&q[0])

	return sumcheck.NewBookKeepingTable(table)
}

func cipherTableGeneratorMimc(q []fr.Element) sumcheck.BookKeepingTable {
	// cipher(q, hR, hL) = 1 iff (q, hR, hL) == (0, 1, 0)
	// After we fold it on q, the table holds the values (0 0 q 0)
	table := make([]fr.Element, 4)
	var one fr.Element
	one.SetOne()
	table[2].Sub(&one, &q[0])

	return sumcheck.NewBookKeepingTable(table)
}

func finCipherTableGeneratorMimc(_ []fr.Element) sumcheck.BookKeepingTable {
	// No folding as bGs[last_layer] = 0
	table := make([]fr.Element, 4)
	table[2].SetOne()
	return sumcheck.NewBookKeepingTable(table)
}

func createTransitionFuncMimc(ark fr.Element) gkr.TransitionFunc {
	return func(v []fr.Element) []fr.Element {
		// Make sure the user passes a pair long vector
		bN := len(v) / 2
		if bN*2 != len(v) {
			panic("Passed an odd valued vector to the transition function")
		}

		res := make([]fr.Element, len(v))

		for i := 0; i < bN; i++ {
			// res[i] = (v[i] + ark)^7 + v[i+bN]
			res[i].Add(&v[i], &ark)
			// Now powers 7
			hash.SBoxInplace(&res[i])
			res[i].Add(&res[i], &v[i+bN])
			// ie: we just copy
			res[i+bN] = v[i+bN]
		}

		return res
	}
}

func createFinTransitionFuncMimc(ark fr.Element) gkr.TransitionFunc {
	return func(v []fr.Element) []fr.Element {
		// Make sure the user passes a pair long vector
		bN := len(v) / 2
		if bN*2 != len(v) {
			panic("Passed an odd valued vector to the transition function")
		}

		res := make([]fr.Element, bN)
		for i := 0; i < bN; i++ {
			// res[i] = (v[i] + ark)^7 + v[i+bN]
			res[i].Add(&v[i], &ark)
			// Now powers 7
			hash.SBoxInplace(&res[i])
			res[i].Add(&res[i], &v[i+bN])
		}

		return res
	}
}

// CreateMimcCircuit returns the GKR MIMC proving circuit
func CreateMimcCircuit() gkr.Circuit {
	nRounds := 91
	gates := make([][]sumcheck.Gate, nRounds)
	transitionFuncs := make([]gkr.TransitionFunc, nRounds)
	staticTableGens := make([][]gkr.TableGenerator, nRounds)
	bGs := make([]int, nRounds+1) // (91 * [1]) | [0]

	for i := 0; i < nRounds-1; i++ {
		gates[i] = []sumcheck.Gate{sumcheck.CipherGate{Ark: hash.Arks[i]}, sumcheck.CopyGate{}}
		transitionFuncs[i] = createTransitionFuncMimc(hash.Arks[i])
		staticTableGens[i] = []gkr.TableGenerator{
			cipherTableGeneratorMimc,
			copyTableGeneratorMimc,
		}
		bGs[i] = 1
	}

	gates[nRounds-1] = []sumcheck.Gate{sumcheck.CipherGate{Ark: hash.Arks[nRounds-1]}}
	transitionFuncs[nRounds-1] = createFinTransitionFuncMimc(hash.Arks[nRounds-1])
	staticTableGens[nRounds-1] = []gkr.TableGenerator{
		finCipherTableGeneratorMimc,
	}
	bGs[nRounds-1] = 1 // And the last one remains at zero, as initialized

	return gkr.NewCircuit(bGs, gates, transitionFuncs, staticTableGens)
}
