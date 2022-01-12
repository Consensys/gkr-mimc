package circuit

import (
	"github.com/AlexandreBelling/gnark/frontend"
	"github.com/consensys/gkr-mimc/snark/polynomial"
)

// GetCopyTable returns a prefolded copy table for the intermediate rounds
func GetCopyTable(cs frontend.API, Q []frontend.Variable) polynomial.MultilinearByValues {
	return polynomial.NewMultilinearByValues([]frontend.Variable{
		frontend.Variable(0),
		frontend.Variable(0),
		Q[0],
		frontend.Variable(0),
	})
}

// GetCipherTable returns a prefolded cipher table for the intermediate rounds
func GetCipherTable(cs frontend.API, Q []frontend.Variable) polynomial.MultilinearByValues {
	return polynomial.NewMultilinearByValues([]frontend.Variable{
		frontend.Variable(0),
		frontend.Variable(0),
		cs.Sub(1, Q[0]),
		frontend.Variable(0),
	})
}

// GetFinalCipherTable returns a prefolded cipher table for the intermediate rounds
func GetFinalCipherTable(cs frontend.API, Q []frontend.Variable) polynomial.MultilinearByValues {
	return polynomial.NewMultilinearByValues([]frontend.Variable{
		frontend.Variable(0),
		frontend.Variable(0),
		frontend.Variable(1),
		frontend.Variable(0),
	})
}
