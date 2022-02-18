package polynomial

import (
	"fmt"

	"github.com/consensys/gkr-mimc/poly"
	"github.com/consensys/gnark/frontend"
)

// MultiLin represents a multilinear polynomial by its values
type MultiLin []frontend.Variable

// AllocateMultilinear returns an empty multilinear with a given size
func AllocateMultilinear(nVars int) MultiLin {
	size := 1 << nVars
	return NewMultilinearByValues(make([]frontend.Variable, size))
}

// Assign a preallocated Multilinear with the given values
func (m MultiLin) Assign(values poly.MultiLin) {
	if len(values) != len(m) {
		panic(fmt.Sprintf("Inconsistent assignment expected len %v but got %v", len(m), len(values)))
	}
	for i, c := range values {
		m[i] = c
	}
}

// NewMultilinearByValues is the default constructor
func NewMultilinearByValues(Table []frontend.Variable) MultiLin {
	return Table
}

// DeepCopy returns a deepcopied value
func (m MultiLin) DeepCopy() MultiLin {
	tableDC := make([]frontend.Variable, len(m))
	copy(tableDC, m)
	return NewMultilinearByValues(tableDC)
}

// Fold partially evaluates the polynomial on one of the variable
func (m *MultiLin) Fold(cs frontend.API, x frontend.Variable) {
	k := len(*m) / 2
	for i := 0; i < k; i++ {
		tmpLinExp := cs.Sub((*m)[i+k], (*m)[i])
		// cs.LinearExpression(
		// 	cs.Term(m[i+k], big.NewInt(1)),
		// 	cs.Term(m[i], big.NewInt(-1)),
		// )
		tmp := cs.Mul(tmpLinExp, x)
		// Ideally we replace this by a r1c.LinearExpression too ...
		(*m)[i] = cs.Add((*m)[i], tmp)
	}
	*m = (*m)[:k]
}

// Eval the multilinear polynomial
func (m MultiLin) Eval(cs frontend.API, xs []frontend.Variable) frontend.Variable {
	f := m.DeepCopy()
	for _, x := range xs {
		// Repeatedly fold the table
		f.Fold(cs, x)
	}
	return f[0]
}
