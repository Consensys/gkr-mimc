package gadget

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/notinternal/backend/bn254/cs"
)

// R1CS wraps gnarks r1cs to add its own datas
type R1CS struct {
	r1cs cs.R1CS
	// Maps all subparts of the multiexp to their respective inputs indices
	pubGkrIo, privGkrIo, pubGkrVarID              []int
	pubNotGkrVarID, privNotGkrVarID, privGkrVarID []int
}

// Wraps the gnark circuit compiler
// Will only work on groth16 with bn254
func (c *Circuit) Compile() (R1CS, error) {

	// Compile the variables
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, c)
	if err != nil {
		return R1CS{}, err
	}

	priv, sec, pub := r1cs.GetNbVariables()
	priv = priv + sec

	// Map of the variable IDs for deduplication
	// And map to a position
	varIdToPosition := make(map[int]int)

	// Map every Gkr variable IDs to their occurence in the ioStore
	for ioPosition, varId := range append(
		c.Gadget.ioStore.inputsVarIds,
		c.Gadget.ioStore.outputsVarIds...,
	) {
		_, ok := varIdToPosition[varId]
		if !ok {
			varIdToPosition[varId] = ioPosition
		}
	}

	// Creates the maps to perform the multiexponentiations
	pubGkrIo := make([]int, pub)
	privGkrVarID := make([]int, pub)
	privGkrIo := make([]int, priv)

	// Now the variable IDs maps
	pubGkrVarID := make([]int, pub)
	pubNotGkrVarID := make([]int, priv)
	privNotGkrVarID := make([]int, priv)

	// For all possible public variable IDs
	for varId := 0; varId < pub; varId++ {
		ioPosition, ok := varIdToPosition[varId]
		if ok {
			// Gkr variable
			pubGkrIo = append(pubGkrIo, ioPosition)
			pubGkrVarID = append(pubGkrVarID, varId)
		} else {
			// Non Gkr variable
			pubNotGkrVarID = append(pubNotGkrVarID, varId)
		}
	}

	// For all possible private variable IDs
	for varId := pub; varId < pub+priv; varId++ {
		ioPosition, ok := varIdToPosition[varId]
		if ok {
			// Gkr variable
			privGkrIo = append(privGkrIo, ioPosition)
			privGkrVarID = append(privGkrVarID, varId)
		} else {
			// Not Gkr variable
			privNotGkrVarID = append(privNotGkrVarID, varId)
		}
	}

	return R1CS{
		r1cs:            *r1cs.(*cs.R1CS),
		pubGkrIo:        pubGkrIo,
		pubGkrVarID:     pubGkrVarID,
		pubNotGkrVarID:  pubNotGkrVarID,
		privGkrIo:       privGkrIo,
		privNotGkrVarID: privNotGkrVarID,
	}, nil
}
