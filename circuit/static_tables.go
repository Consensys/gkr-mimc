package circuit

import (
	"fmt"

	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gnark/frontend"

	snarkPoly "github.com/consensys/gkr-mimc/snark/polynomial"
)

// Degrees of the combinated gates on the current layer
func (l *Layer) Degrees() (int, int, int) {
	degHL, degHR, degHPrime := 0, 0, 0
	for _, gate := range l.Gates {
		dHl, dHr, dHprime := gate.Degrees()
		degHL = common.Max(degHL, dHl)
		degHR = common.Max(degHR, dHr)
		degHPrime = common.Max(degHPrime, dHprime)
	}
	return degHL + 1, degHR + 1, degHPrime + 1
}

// Returns the static tables as constants, for the gate number "i"
func (l *Layer) GnarkEvalStaticTables(cs *frontend.API, i int, q []frontend.Variable) snarkPoly.MultilinearByValues {
	gateID := l.Gates[i].ID()
	// Usefull integer constants
	gL := 1 << l.BGInputs
	one := cs.Constant(1)
	// The tab must be filled with zeroes
	tab := make([]frontend.Variable, (1 << (2 * l.BGInputs)))
	for i := range tab {
		tab[i] = cs.Constant(0)
	}

	for _, wire := range l.Wires {
		if wire.Gate.ID() == gateID {
			qTmp := one
			// Sanity check: the length of q should be consistent with the circuit design
			if wire.O > 1<<len(q) {
				panic(fmt.Sprintf("q was of length %v but wire.O was %v", len(q), wire.O))
			}

			// In order to save constraints, we prefold the table implicitly
			for i := range q {
				// ie: If the i-th bit of oTmp is "1"
				if (wire.O>>i)&1 == 1 {
					qTmp = cs.Mul(qTmp, q[i])
				} else {
					qTmp = cs.Mul(qTmp, cs.Sub(one, q[i]))
				}
			}

			k := gL*wire.L + wire.R
			tab[k] = cs.Add(tab[k], qTmp)
		}
	}

	return snarkPoly.NewMultilinearByValues(tab)
}

// Combine returns an evaluation of the GKR layer
func (l *Layer) GnarkCombine(
	cs *frontend.API,
	q, qPrime, hL, hR, hPrime []frontend.Variable,
	vL, vR frontend.Variable,
) frontend.Variable {
	res := cs.Constant(0)
	hLhR := append(append([]frontend.Variable{}, hL...), hR...)

	for i := range l.Gates {
		tab := l.GnarkEvalStaticTables(cs, i, q)
		res = cs.Add(res, cs.Mul(tab.Eval(cs, hLhR), l.Gates[i].GnarkEval(cs, vL, vR)))
	}

	return cs.Mul(res, snarkPoly.EqEval(cs, qPrime, hPrime))
}

// CombineWithLinearComb returns a linear comb of 2 evaluation of the GKR layer
// for 2 values of q: qL and qR
func (l *Layer) CombineWithLinearComb(
	cs *frontend.API,
	qL, qR, qPrime, hL, hR, hPrime []frontend.Variable,
	lambdaL, lambdaR, vL, vR frontend.Variable,
) frontend.Variable {
	res := cs.Constant(0)
	hLhR := append(append([]frontend.Variable{}, hL...), hR...)

	for i := range l.Gates {
		tabL := l.GnarkEvalStaticTables(cs, i, qL)
		tabR := l.GnarkEvalStaticTables(cs, i, qR)

		tabEval := cs.Add(
			cs.Mul(lambdaL, tabL.Eval(cs, hLhR)),
			cs.Mul(lambdaR, tabR.Eval(cs, hLhR)),
		)
		res = cs.Add(res, cs.Mul(tabEval, l.Gates[i].GnarkEval(cs, vL, vR)))
	}
	return cs.Mul(res, snarkPoly.EqEval(cs, qPrime, hPrime))
}
