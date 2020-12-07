package polynomial

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
)

// MultilinearByValues represents a multilinear polynomial by its values
type MultilinearByValues struct {
	Table []frontend.Variable
}

// AllocateMultilinear returns an empty multilinear with a given size
func AllocateMultilinear(nVars int) MultilinearByValues {
	size := 1 << nVars
	return NewMultilinearByValues(make([]frontend.Variable, size))
}

// Assign a preallocated Multilinear with the given values
func (m *MultilinearByValues) Assign(values []interface{}) {
	if len(values) != len(m.Table) {
		panic(fmt.Sprintf("Inconsistent assignment expected len %v but got %v", len(m.Table), len(values)))
	}
	for i, c := range values {
		m.Table[i].Assign(c)
	}
}

// NewMultilinearByValues is the default constructor
func NewMultilinearByValues(Table []frontend.Variable) MultilinearByValues {
	return MultilinearByValues{Table: Table}
}

// DeepCopy returns a deepcopied value
func (m MultilinearByValues) DeepCopy() MultilinearByValues {
	tableDC := make([]frontend.Variable, len(m.Table))
	copy(tableDC, m.Table)
	return NewMultilinearByValues(tableDC)
}

// Fold partially evaluates the polynomial on one of the variable
func (m *MultilinearByValues) Fold(cs *frontend.ConstraintSystem, x frontend.Variable) {
	k := len(m.Table) / 2
	for i := 0; i < k; i++ {
		tmp := cs.Sub(m.Table[i+k], m.Table[i])
		tmp = cs.Mul(tmp, x)
		m.Table[i] = cs.Add(m.Table[i], tmp)
	}
	m.Table = m.Table[:k]
}

// Eval the multilinear polynomial
func (m MultilinearByValues) Eval(cs *frontend.ConstraintSystem, xs []frontend.Variable) frontend.Variable {
	f := m.DeepCopy()
	for _, x := range xs {
		// Repeatedly fold the table
		f.Fold(cs, x)
	}
	return f.Table[0]
}

// EvalMixed the multilinear polynomial
// We must have len(qL) == len(qR)
// And len(Table) = 2 ** len(qL) + len(qPrime)
func (m MultilinearByValues) EvalMixed(
	cs *frontend.ConstraintSystem,
	qL, qR, qPrime []frontend.Variable,
) (vL, vR frontend.Variable) {
	// The function proceeds by putting in common the evaluations over qPrime
	// to save a maximum of space
	nChunks := 1 << len(qL)
	chunkSize := len(m.Table) / nChunks
	intermediateTable := make([]frontend.Variable, nChunks)

	// Evaluate each portion of the table on qPrime. For different values of q.
	for i := range intermediateTable {
		multlin := NewMultilinearByValues(m.Table[i*chunkSize : (i+1)*chunkSize])
		intermediateTable[i] = multlin.Eval(cs, qPrime)
	}
	intermediatePoly := NewMultilinearByValues(intermediateTable)
	return intermediatePoly.Eval(cs, qL), intermediatePoly.Eval(cs, qR)
}
