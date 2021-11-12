package gkr

import (
	"github.com/consensys/gkr-mimc/snark/polynomial"

	"github.com/consensys/gnark/frontend"
)

// StaticTableGenerator returns a prefolded static table
type StaticTableGenerator func(cs *frontend.API, Q []frontend.Variable) polynomial.MultilinearByValues
