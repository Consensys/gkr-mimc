package gkr

import (
	"gkr-mimc/circuit/polynomial"

	"github.com/consensys/gnark/frontend"
)

// StaticTableGenerator returns a prefolded static table
type StaticTableGenerator func(cs *frontend.ConstraintSystem, Q []frontend.Variable) polynomial.MultilinearByValues
