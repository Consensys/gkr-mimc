package gadget

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
)

// R1CS wraps gnarks r1cs to add its own datas
type R1CS struct {
	r1cs         frontend.CompiledConstraintSystem
	inputsVarIds []int
	outputVarIds []int
}

func (c *Circuit) Compile() (R1CS, error) {
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, c)
	if err != nil {
		return R1CS{}, err
	}

	return R1CS{
		r1cs:         r1cs,
		inputsVarIds: c.Gadget.ioStore.inputsVarIds,
		outputVarIds: c.Gadget.ioStore.outputsVarIds,
	}, nil
}
