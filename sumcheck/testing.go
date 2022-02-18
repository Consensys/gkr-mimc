package sumcheck

import (
	"github.com/consensys/gkr-mimc/circuit"
	"github.com/consensys/gkr-mimc/circuit/gates"
	"github.com/consensys/gkr-mimc/poly"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func InitializeCipherGateInstance(bn int) (X []poly.MultiLin, claims []fr.Element, qPrime [][]fr.Element, gate circuit.Gate) {

	q := make([]fr.Element, bn)
	for i := range q {
		q[i].SetUint64(2)
	}

	gate = gates.NewCipherGate(fr.NewElement(1))

	L := poly.MakeLarge(1 << bn)
	R := poly.MakeLarge(1 << bn)

	for i := range L {
		L[i].SetUint64(uint64(i))
		R[i].SetUint64(uint64(i))
	}

	inst_ := instance{
		X:      []poly.MultiLin{L, R},
		gate:   gate,
		degree: gate.Degree() + 1,
		Eq:     poly.MakeLarge(1 << bn),
	}
	poly.FoldedEqTable(inst_.Eq, q)
	claim := Evaluation(gate, [][]fr.Element{q}, []fr.Element{}, L, R)

	return []poly.MultiLin{L, R}, []fr.Element{claim}, [][]fr.Element{q}, gate
}

func InitializeMultiInstance(bn, ninstance int) (X []poly.MultiLin, claims []fr.Element, qPrime [][]fr.Element, gate circuit.Gate) {

	n := 1 << bn
	gate = gates.IdentityGate{}

	// Create the qs
	qs := make([][]fr.Element, ninstance)
	for i := range qs {
		q := make([]fr.Element, bn)
		for j := range q {
			q[j].SetUint64(uint64(i*j + i))
		}
		qs[i] = q
	}

	L := poly.MakeLarge(n)
	R := poly.MakeLarge(n)

	for i := range L {
		L[i].SetUint64(uint64(i))
		R[i].SetUint64(uint64(i))
	}

	claims = make([]fr.Element, ninstance)
	for i := range claims {
		claims[i] = Evaluation(gate, [][]fr.Element{qs[i]}, []fr.Element{}, L, R)
	}

	return []poly.MultiLin{L, R}, claims, qs, gate
}
