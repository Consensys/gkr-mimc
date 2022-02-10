package gates

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
)

// CipherGate cipher gate returns vL + (vR + c)^7
type CipherGate struct {
	Ark fr.Element
}

// NewCipherGate construct a new cipher gate given an ark
// CipherGate cipher gate returns vL + (vR + c)^7
func NewCipherGate(ark fr.Element) *CipherGate {
	return &CipherGate{Ark: ark}
}

// ID returns the id of the cipher gate and print the ark as well
func (c *CipherGate) ID() string { return fmt.Sprintf("CipherGate-%v", c.Ark.String()) }

// Eval returns vL + (vR + c)^7
func (c *CipherGate) Eval(res, vL, vR *fr.Element) {
	// tmp = vR + Ark
	var tmp fr.Element
	tmp.Add(vR, &c.Ark)
	// res = tmp^7
	res.Square(&tmp)
	res.Mul(res, &tmp)
	res.Square(res)
	res.Mul(res, &tmp)
	// Then add vL
	res.Add(res, vL)
}

// GnarkEval performs the cipher operation on gnark variables
func (c *CipherGate) GnarkEval(cs frontend.API, vL, vR frontend.Variable) frontend.Variable {
	tmp := cs.Add(vR, frontend.Variable(c.Ark))
	cipher := cs.Mul(tmp, tmp)
	cipher = cs.Mul(cipher, tmp)
	cipher = cs.Mul(cipher, cipher)
	cipher = cs.Mul(cipher, tmp)
	return cs.Add(cipher, vL)
}

// Degree returns the Degree of the gate on hL, hR and hPrime
func (c *CipherGate) Degree() (degHPrime int) {
	return 7
}
