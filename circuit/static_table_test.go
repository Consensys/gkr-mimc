package circuit

import (
	"github.com/consensys/gkr-mimc/snark/polynomial"
	"github.com/consensys/gnark/frontend"
)

// GetCopyTable returns a prefolded copy table for the intermediate rounds
func GetCopyTable(cs *frontend.API, Q []frontend.Variable) polynomial.MultilinearByValues {
	return polynomial.NewMultilinearByValues([]frontend.Variable{
		cs.Constant(0),
		cs.Constant(0),
		Q[0],
		cs.Constant(0),
	})
}

// GetCipherTable returns a prefolded cipher table for the intermediate rounds
func GetCipherTable(cs *frontend.API, Q []frontend.Variable) polynomial.MultilinearByValues {
	return polynomial.NewMultilinearByValues([]frontend.Variable{
		cs.Constant(0),
		cs.Constant(0),
		cs.Sub(1, Q[0]),
		cs.Constant(0),
	})
}

// GetFinalCipherTable returns a prefolded cipher table for the intermediate rounds
func GetFinalCipherTable(cs *frontend.API, Q []frontend.Variable) polynomial.MultilinearByValues {
	return polynomial.NewMultilinearByValues([]frontend.Variable{
		cs.Constant(0),
		cs.Constant(0),
		cs.Constant(1),
		cs.Constant(0),
	})
}
