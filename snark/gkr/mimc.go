package gkr

import (
	"github.com/consensys/gkr-mimc/hash"
	"github.com/consensys/gkr-mimc/snark/polynomial"

	"github.com/consensys/gnark/frontend"
)

// CreateMimcCircuit creates a GKR circuit for Mimc
func CreateMimcCircuit() Circuit {
	nLayers := hash.MimcRounds
	layers := make([]Layer, hash.MimcRounds)

	for i := 0; i < nLayers-1; i++ {
		layers[i] = Layer{
			Gates: []Gate{
				CipherGate(hash.Arks[i]),
				CopyGate(),
			},
			StaticTable: []StaticTableGenerator{
				GetCipherTable,
				GetCopyTable,
			},
			BG:        1,
			DegHL:     2,
			DegHR:     8,
			DegHPrime: 8,
		}
	}

	layers[nLayers-1] = Layer{
		Gates:       []Gate{CipherGate(hash.Arks[nLayers-1])},
		StaticTable: []StaticTableGenerator{GetFinalCipherTable},
		BG:          1,
		DegHL:       2,
		DegHR:       8,
		DegHPrime:   8,
	}

	return Circuit{
		Layers: layers,
		BGOut:  0,
	}

}

// GetCopyTable returns a prefolded copy table for the intermediate rounds
func GetCopyTable(cs frontend.API, Q []frontend.Variable) polynomial.MultilinearByValues {
	return polynomial.NewMultilinearByValues([]frontend.Variable{
		cs.Constant(0),
		cs.Constant(0),
		Q[0],
		cs.Constant(0),
	})
}

// GetCipherTable returns a prefolded cipher table for the intermediate rounds
func GetCipherTable(cs frontend.API, Q []frontend.Variable) polynomial.MultilinearByValues {
	return polynomial.NewMultilinearByValues([]frontend.Variable{
		cs.Constant(0),
		cs.Constant(0),
		cs.Sub(1, Q[0]),
		cs.Constant(0),
	})
}

// GetFinalCipherTable returns a prefolded cipher table for the intermediate rounds
func GetFinalCipherTable(cs frontend.API, Q []frontend.Variable) polynomial.MultilinearByValues {
	return polynomial.NewMultilinearByValues([]frontend.Variable{
		cs.Constant(0),
		cs.Constant(0),
		cs.Constant(1),
		cs.Constant(0),
	})
}
