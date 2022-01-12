package gadget

import "github.com/AlexandreBelling/gnark/frontend"

type CircuitBaseline struct {
	X []frontend.Variable
}

type CircuitWithGkr struct {
	X []frontend.Variable
}

func (c *CircuitBaseline) Define(cs frontend.API) error {
	return nil
}

func (c *CircuitWithGkr) Define(cs frontend.API, gadget *GkrGadget) error {
	return nil
}
