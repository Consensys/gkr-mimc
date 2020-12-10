package gkr

import (
	"gkr-mimc/snark/polynomial"

	"github.com/consensys/gnark/frontend"
)

// StaticTableGenerator returns a prefolded static table
type StaticTableGenerator func(cs *frontend.ConstraintSystem, Q []frontend.Variable) polynomial.MultilinearByValues
