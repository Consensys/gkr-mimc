package polynomial

import (
	"math/big"

	"github.com/consensys/gnark/backend/r1cs/r1c"
	//"github.com/consensys/gnark/cs"

	"github.com/consensys/gnark/frontend"
)

// MultilinearByLinExp represents a multilinear polynomial
// with values represented as Linear Expressions (LinExp).
type MultilinearByLinExp struct {
	Table []r1c.LinearExpression
}

// NewMultilinearByLinExp Default constructor
func NewMultilinearByLinExp(cs *frontend.ConstraintSystem, Table []frontend.Variable) MultilinearByLinExp {
	TableLinExp := make([]r1c.LinearExpression, len(Table))
	for i, x := range Table {
		TableLinExp[i] = VariableToLinExp(cs, x)
	}
	return MultilinearByLinExp{Table: TableLinExp}
}

// VariableToLinExp converts a single frontend.variable x to
// the r1c.LinearExpression `` (x, 1) ''
func VariableToLinExp(cs *frontend.ConstraintSystem, x frontend.Variable) r1c.LinearExpression {
	return r1c.LinearExpression{
		cs.Term(x, big.NewInt(1)),
	}
}

// NegateTerm converts a term of the form (x, n) to (x, -n)
func NegateTerm(t r1c.Term) r1c.Term {
	coeffvalue, coeffID, constraintID, constraintVisibility := t.Unpack()
	coeffvalue = 0 - coeffvalue
	return r1c.Pack(constraintID, coeffID, constraintVisibility, coeffvalue)
}

// NegateLinExp applies NegateTerm to every term in a LinearExpression
func NegateLinExp(l r1c.LinearExpression) r1c.LinearExpression {
	res := make(r1c.LinearExpression, len(l))
	for i, term := range l {
		res[i] = NegateTerm(term)
	}
	return res
}

// MultilinearByValuesToMultilinearByLinExp converts a MultinlinearByValues
// to a MultilinearByLinExp where all values x are replaced by the one term
// linear expression cs.Term(x, 1).
func (m *MultilinearByValues) MultilinearByValuesToMultilinearByLinExp(cs *frontend.ConstraintSystem) MultilinearByLinExp {
	return NewMultilinearByLinExp(cs, m.Table)
}

// Fold partially evaluates the polynomial on one of the variable
func (m *MultilinearByLinExp) Fold(cs *frontend.ConstraintSystem, x frontend.Variable) {
	k := len(m.Table) / 2
	for i := 0; i < k; i++ {
		// tmp <->
		tmp := cs.MergeLinearExpressions(
			m.Table[i+k],
			NegateLinExp(m.Table[i]),
		)
		tmp = VariableToLinExp(cs, cs.Mul(x, tmp))
		m.Table[i] = cs.MergeLinearExpressions(m.Table[i], tmp)
	}
	m.Table = m.Table[:k]
}

// Eval2 is an alternative way to evaluate a MultilinearByValues using LinearExpressions
func (m MultilinearByValues) Eval2(cs *frontend.ConstraintSystem, xs []frontend.Variable) frontend.Variable {
	f := m.MultilinearByValuesToMultilinearByLinExp(cs)
	for _, x := range xs {
		// Repeatedly fold the table
		f.Fold(cs, x)
	}
	return cs.Mul(cs.Constant(1), f.Table[0])
}
