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

// Eval returns (vR + c + vL)^7, on the range of output
func (c *CipherGate) EvalBatch(res []fr.Element, xs ...[]fr.Element) {

	ls := xs[0]
	rs := xs[1]

	var tmp fr.Element

	for i := range res {
		// tmp = vR + Ark + vL
		tmp.Add(&rs[i], &c.Ark)
		tmp.Add(&tmp, &ls[i])
		// res = tmp^7
		res[i].Square(&tmp)
		res[i].Mul(&res[i], &tmp)
		res[i].Square(&res[i])
		res[i].Mul(&res[i], &tmp)
	}
}

// Eval returns (vL + vR + c)^7
func (c *CipherGate) Eval(res *fr.Element, xs ...*fr.Element) {
	// tmp = vR + Ark + vL
	var tmp fr.Element
	tmp.Add(xs[1], &c.Ark)
	tmp.Add(&tmp, xs[0])
	// res = tmp^7
	res.Square(&tmp)
	res.Mul(res, &tmp)
	res.Square(res)
	res.Mul(res, &tmp)
}

// GnarkEval performs the cipher operation on gnark variables
func (c *CipherGate) GnarkEval(cs frontend.API, xs ...frontend.Variable) frontend.Variable {
	tmp := cs.Add(xs[1], frontend.Variable(c.Ark))
	cipher := cs.Mul(tmp, tmp)
	cipher = cs.Mul(cipher, tmp)
	cipher = cs.Mul(cipher, cipher)
	cipher = cs.Mul(cipher, tmp)
	return cs.Add(cipher, xs[0])
}

// Degree returns the Degree of the gate on hL, hR and hPrime
func (c *CipherGate) Degree() (degHPrime int) {
	return 7
}
