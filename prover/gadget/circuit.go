package gadget

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

// Interface to be implemented by any circuit willing to use Gkr
type CircuitUsingGkr interface {
	Define(curveID ecc.ID, cs frontend.API, gadget *GkrGadget) error
}

// Generic wrapper circuit in which, we can plug any circuit using
// Gkr. The wrapper holds all the logic for the proving etc...
type Circuit struct {
	Gadget       GkrGadget
	InnerCircuit CircuitUsingGkr
}

// Wraps the given circuit into a `Circuit` object
func WrapCircuitUsingGkr(c CircuitUsingGkr, opts ...GkrOption) Circuit {
	w := Circuit{
		InnerCircuit: c,
		Gadget:       *NewGkrGadget(),
	}
	// Applies the options
	for _, opt := range opts {
		opt(&w)
	}
	return w
}

// Implements `gnark`s circuit interface
func (c *Circuit) Define(curveID ecc.ID, cs frontend.API) error {
	if err := c.InnerCircuit.Define(curveID, cs, &c.Gadget); err != nil {
		return err
	}
	c.Gadget.Close(cs)
	return nil
}

// Assigns for the subcircuit
func (c *Circuit) Assign() {
	c.Gadget.InitialRandomness.Assign(0)
}

// Options for the `Circuit` constructor
type GkrOption func(c *Circuit)

// Mutates the chunkSize of the circuit
func WithChunkSize(chunkSize int) GkrOption {
	return func(c *Circuit) {
		c.Gadget.chunkSize = chunkSize
	}
}

// Mutates the chunkSize of the circuit
func WithNCore(n int) GkrOption {
	return func(c *Circuit) {
		c.Gadget.gkrNCore = n
	}
}
