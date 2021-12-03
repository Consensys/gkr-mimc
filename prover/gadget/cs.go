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
	// Pointer to the proving key
	provingKey *ProvingKey
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
	ioStore := &c.Gadget.ioStore

	// Map every Gkr variable IDs to their occurence in the ioStore
	ioVarIDs := append(ioStore.inputsVarIds, ioStore.outputsVarIds...)
	ioIsConstant := append(ioStore.inputsIsConstant, ioStore.outputsIsConstant...)

	for ioPosition, varId := range ioVarIDs {
		constantVar := ioIsConstant[ioPosition]
		_, alreadySeen := varIdToPosition[varId]
		if !alreadySeen && !constantVar {
			varIdToPosition[varId] = ioPosition
		}
	}

	// Creates the maps to perform the multiexponentiations
	pubGkrIo := make([]int, 0, pub)
	pubGkrVarID := make([]int, 0, pub)
	privGkrVarID := make([]int, 0, pub)

	// Now the variable IDs maps
	privGkrIo := make([]int, 0, priv)
	pubNotGkrVarID := make([]int, 0, priv)
	privNotGkrVarID := make([]int, 0, priv)

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
