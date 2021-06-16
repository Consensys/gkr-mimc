package gkr

import (
	"gkr-mimc/snark/polynomial"

	"github.com/ConsenSys/gnark/frontend"
)

// StaticTableGenerator returns a prefolded static table
type StaticTableGenerator func(cs *frontend.ConstraintSystem, Q []frontend.Variable) polynomial.MultilinearByValues
