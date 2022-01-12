package gadget

type CircuitBaseline struct {
	X []frontend.Variable
}

type CircuitWithGkr struct {
	X []frontend.Variable
}

func (c *CircuitBaseline) Define(curveID ecc.ID, cs frontend.API) error {
	for x := range c.X {
		_ = 
	}
	return nil
}

func (c *CircuitWithGkr) Define(curveID ecc.ID, cs frontend.API, gadget *GkrGadget) error {
	return nil
}
