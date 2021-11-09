package gadget

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

type CircuitUsingGkr interface {
	Define(curveID ecc.ID, cs *frontend.ConstraintSystem, gadget *GkrGadget) error
}

type Circuit struct {
	InnerCircuit CircuitUsingGkr
	Gadget       GkrGadget
}

func WrapCircuitUsingGkr(c CircuitUsingGkr) Circuit {
	return Circuit{
		InnerCircuit: c,
		Gadget:       *NewGkrGadget(),
	}
}

func (c *Circuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	if err := c.InnerCircuit.Define(curveID, cs, &c.Gadget); err != nil {
		return err
	}

	c.Gadget.Close(cs)
	return nil
}

func (c *Circuit) Assign(i CircuitUsingGkr) {
	c.InnerCircuit = i
}
