package gates

import (
	"fmt"

	"github.com/AlexandreBelling/gnark/frontend"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
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

// EvalManyVR performs cipher evaluations of many vRs values by one vL value
// Nothing special to do here
func (c *CipherGate) EvalManyVR(res []fr.Element, vL *fr.Element, vRs []fr.Element) {
	var tmp fr.Element
	for i := 0; i < len(vRs); i++ {
		// tmp = vR + Ark
		tmp.Add(&vRs[i], &c.Ark)
		// res = tmp^7
		res[i].Square(&tmp)
		res[i].Mul(&res[i], &tmp)
		res[i].Square(&res[i])
		res[i].Mul(&res[i], &tmp)
		// Then add vL
		res[i].Add(&res[i], vL)
	}
}

// EvalManyVL performs an element-wise cipher of many vLs values by one vR
// This one is optimized to only do the vL exponentiation once
func (c *CipherGate) EvalManyVL(res, vLs []fr.Element, vR *fr.Element) {
	// tmp = vR + Ark
	var tmp, right fr.Element
	tmp.Add(vR, &c.Ark)
	// right = tmp^7
	right.Square(&tmp)
	right.Mul(&right, &tmp)
	right.Square(&right)
	right.Mul(&right, &tmp)

	for i := 0; i < len(vLs); i++ {
		res[i].Add(&right, &vLs[i])
	}
}

// Degrees returns the degrees of the gate on hL, hR and hPrime
func (c *CipherGate) Degrees() (degHL, degHR, degHPrime int) {
	return 1, 7, 7
}
