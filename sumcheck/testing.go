package sumcheck

import (
	"gkr-mimc/polynomial"

	"github.com/consensys/gurvy/bn256/fr"
)

// InitializeProverForTests creates a test prover
func InitializeProverForTests(bN int) Prover {

	var zero, one, two fr.Element
	one.SetOne()
	two.SetUint64(2)

	// Fold for q', q = [2, 2, 2 ,2 ...] 2
	// cipher: q = 0, qL = 1, qR = 0
	// copy: q = 1, qL = 1, qR = 0
	qPrime := make([]fr.Element, bN)
	for i := range qPrime {
		qPrime[i] = two
	}
	eq := polynomial.PrefoldedEqTable(qPrime)
	cipher := polynomial.NewBookKeepingTable([]fr.Element{zero, zero, one, zero, zero, zero, zero, zero})
	copy := polynomial.NewBookKeepingTable([]fr.Element{zero, zero, zero, zero, zero, zero, one, zero})
	cipher.Fold(two)
	copy.Fold(two)

	// Initialize the values of V
	v := make([]fr.Element, 1<<(bN+1))
	for i := range v {
		v[i].SetUint64(uint64(i))
	}
	vL := polynomial.NewBookKeepingTable(v)
	vR := vL.DeepCopy()

	return NewProver(
		vL, vR, eq,
		[]Gate{CopyGate{}, CipherGate{Ark: two}},
		[]polynomial.BookKeepingTable{copy, cipher},
	)
}
