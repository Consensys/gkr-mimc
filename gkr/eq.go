package gkr

import (
	"github.com/consensys/gurvy/bn256/fr"
)

// EvalEq computes Eq(q1', ... , qn', h1', ... , hn') = Π_1^n Eq(qi', hi')
// where Eq(x,y) = xy + (1-x)(1-y) = 1 - x - y + xy + xy interpolates
//      _________________
//      |       |       |
//      |   0   |   1   |
//      |_______|_______|
//  y   |       |       |
//      |   1   |   0   |
//      |_______|_______|
//
//              x
func EvalEq(qPrime, nextQPrime []fr.Element) fr.Element {
	var res, nxt, one, sum fr.Element
	one.SetOne()
	res.SetOne()
	for i := 0; i < len(qPrime); i++ {
		nxt.Mul(&qPrime[i], &nextQPrime[i]) // nxt <- qi' * hi'
		nxt.Add(&nxt, &nxt)                 // nxt <- 2 * qi' * hi'
		nxt.Add(&nxt, &one)                 // nxt <- 1 + 2 * qi' * hi'
		sum.Add(&qPrime[i], &nextQPrime[i]) // sum <- qi' + hi'
		nxt.Sub(&nxt, &sum)                 // nxt <- 1 + 2 * qi' * hi' - qi' - hi'
		res.Mul(&res, &nxt)                 // res <- res * nxt
	}
	return res
}
