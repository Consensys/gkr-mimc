package gadget

import (
	"github.com/AlexandreBelling/gnark/frontend"
)

// Interface to be implemented by any circuit willing to use Gkr
type CircuitUsingGkr interface {
	Define(cs frontend.API, gadget *GkrGadget) error
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
func (c *Circuit) Define(cs frontend.API) error {
	if err := c.InnerCircuit.Define(cs, &c.Gadget); err != nil {
		return err
	}
	c.Gadget.Close(cs)
	return nil
}

// Assigns for the subcircuit
func (c *Circuit) Assign() {
	c.Gadget.InitialRandomness = 0
}

// Options for the `Circuit` constructor
type GkrOption func(c *Circuit)

// Pass maximal chunk size to the gadget
func WithMinChunkSize(chunkSize int) GkrOption {
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
