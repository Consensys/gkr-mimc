package gkr

import (
	"fmt"
	"gkr-mimc/common"
	"gkr-mimc/sumcheck"
	"testing"

	"github.com/consensys/gurvy/bn256/fr"
	"github.com/stretchr/testify/assert"
)

// We test for the following circuit
//
//	  a + b + (a×b)	  (a+b) × a × b				  c + d + (c×d)	  (c+d) × c × d
//	________|_______________|_________			________|_______________|_________
// 	|	_________		_________	 |		 	|	_________		_________	 |
//	|	|		|		|		|	 |			|	|		|		|		|	 |
//	|	|	+	|		|	×	|	 |			|	|	+	|		|	×	|	 |
//	|	|_______|		|_______|	 |			|	|_______|		|_______|	 |
//	|________________________________|			|________________________________|
//			|				|							|				|
//		  a + b			  a × b						  c + d			  c × d
//	________|_______________|_________			________|_______________|_________
// 	|	_________		_________	 |		 	|	_________		_________	 |
//	|	|		|		|		|	 |			|	|		|		|		|	 |
//	|	|	+	|		|	×	|	 |			|	|	+	|		|	×	|	 |
//	|	|_______|		|_______|	 |			|	|_______|		|_______|	 |
//	|________________________________|			|________________________________|
//			|				|							|				|
//			a				b							c				d
//
// Note: bN = bG = 1.

// addFinTableGenerator is the table generator for the final addition
func addFinTableGenerator(_ []fr.Element) sumcheck.BookKeepingTable {
	addTable := make([]fr.Element, 4)
	addTable[2].SetOne()
	return sumcheck.NewBookKeepingTable(addTable)
}

// addTableGenerator is the TableGenerator for addition
func addTableGenerator(q []fr.Element) sumcheck.BookKeepingTable {
	// add(q, hR, hL) == 1    iff    (q, hR, hL) == (0, 1, 0)
	// thus addTable is zero except addTable[2] = 1-q	(Note: q = q[0])
	addTable := make([]fr.Element, 4)
	var one fr.Element
	one.SetOne()
	addTable[2].Sub(&one, &q[0])
	addBKT := sumcheck.NewBookKeepingTable(addTable)
	return addBKT
}

// mulTableGenerator is the TableGenerator for addition
// mul(q, hR, hL) = 1    iff    (q, hR, hL) = (1, 1, 0)
func mulTableGenerator(q []fr.Element) sumcheck.BookKeepingTable {
	// mul(q, hR, hL) == 1    iff    (q, hR, hL) == (1, 1, 0)
	// thus mulTable is zero except mulTable[2] = q		(Note: q = q[0])
	mulTable := make([]fr.Element, 4)
	mulTable[2].Set(&q[0])
	mulBKT := sumcheck.NewBookKeepingTable(mulTable)
	return mulBKT
}

// Testcase:
//
//	        5	            6				           19				84
//	________|_______________|_________			________|_______________|_________
// 	|	_________		_________	 |		 	|	_________		_________	 |
//	|	|		|		|		|	 |			|	|		|		|		|	 |
//	|	|	+	|		|	×	|	 |			|	|	+	|		|	×	|	 |
//	|	|_______|		|_______|	 |			|	|_______|		|_______|	 |
//	|________________________________|			|________________________________|
//			|				|							|				|
//		    3			    2						    7			   12
//	________|_______________|_________			________|_______________|_________
// 	|	_________		_________	 |		 	|	_________		_________	 |
//	|	|		|		|		|	 |			|	|		|		|		|	 |
//	|	|	+	|		|	×	|	 |			|	|	+	|		|	×	|	 |
//	|	|_______|		|_______|	 |			|	|_______|		|_______|	 |
//	|________________________________|			|________________________________|
//			|				|							|				|
//			1				2							3				4

func trans(vals []fr.Element) []fr.Element {
	res := make([]fr.Element, 4)
	res[0].Add(&vals[0], &vals[2])
	res[2].Mul(&vals[0], &vals[2])
	res[1].Add(&vals[1], &vals[3])
	res[3].Mul(&vals[1], &vals[3])

	return res
}

func finTrans(vals []fr.Element) []fr.Element {
	res := make([]fr.Element, 2)
	res[0].Add(&vals[0], &vals[2])
	res[1].Add(&vals[1], &vals[3])
	return res
}

func TestMultiBGs(t *testing.T) {
	var one fr.Element
	one.SetOne()

	// Writes the bGs
	bGs := []int{1, 1, 0}

	// the combinator is the same at all levels
	gates := [][]sumcheck.Gate{
		[]sumcheck.Gate{sumcheck.AddGate{}, sumcheck.MulGate{}},
		[]sumcheck.Gate{sumcheck.AddGate{}},
	}
	// there is also only one transition function
	transitionFuncs := []TransitionFunc{trans, finTrans}

	// Note: 2 = 2^bN since bN = 1.
	staticTabbleGens := make([][]TableGenerator, 2)
	staticTabbleGens[0] = []TableGenerator{addTableGenerator, mulTableGenerator}
	staticTabbleGens[1] = []TableGenerator{addFinTableGenerator}
	// GKR circuit:
	c := NewCircuit(bGs, gates, transitionFuncs, staticTabbleGens)

	// hL, h' or hR, h'
	inputs := make([]fr.Element, 4)
	inputs[0].SetUint64(uint64(1))
	inputs[1].SetUint64(uint64(3))
	inputs[2].SetUint64(uint64(2))
	inputs[3].SetUint64(uint64(4))

	a := c.GenerateAssignment(inputs)
	inputsV := append([]fr.Element{}, inputs...)
	outputsV := a.LayerAsBKTWithCopy(2).Table

	p := NewProver(c, a)

	proof := p.Prove(1)

	v := NewVerifier(1, c)
	validity := v.Verify(proof, outputsV, inputsV)

	assert.Equal(
		t,
		validity,
		true,
		"Proof invalid.",
	)

	actualValues := make([][]fr.Element, 3)
	// actualValues =	[
	//						[1, 2, 3, 4],
	//						[3, 2, 7, 12],
	//						[5, 19]
	//					]
	actualValues[0] = make([]fr.Element, 4)
	actualValues[0][0].SetUint64(uint64(1))
	actualValues[0][1].SetUint64(uint64(3))
	actualValues[0][2].SetUint64(uint64(2))
	actualValues[0][3].SetUint64(uint64(4))
	actualValues[1] = make([]fr.Element, 4)
	actualValues[1][0].SetUint64(uint64(3))
	actualValues[1][1].SetUint64(uint64(7))
	actualValues[1][2].SetUint64(uint64(2))
	actualValues[1][3].SetUint64(uint64(12))
	actualValues[2] = make([]fr.Element, 2)
	actualValues[2][0].SetUint64(uint64(5))
	actualValues[2][1].SetUint64(uint64(19))

	fmt.Printf("a.values = %v %v %v\n",
		common.FrSliceToString(a.values[0]),
		common.FrSliceToString(a.values[1]),
		common.FrSliceToString(a.values[2]),
	)

	assert.Equal(
		t,
		a.values,
		actualValues,
		"Proof invalid.",
	)
}

func TestGKR(t *testing.T) {
	var one fr.Element
	one.SetOne()

	// Writes the bGs
	bGs := []int{1, 1, 1}

	// the combinator is the same at all levels
	gates := [][]sumcheck.Gate{
		[]sumcheck.Gate{sumcheck.AddGate{}, sumcheck.MulGate{}},
		[]sumcheck.Gate{sumcheck.AddGate{}, sumcheck.MulGate{}},
	}
	// there is also only one transition function
	transitionFuncs := []TransitionFunc{trans, trans}

	// Note: 2 = 2^bN since bN = 1.
	staticTabbleGens := make([][]TableGenerator, 2)
	staticTabbleGens[0] = []TableGenerator{addTableGenerator, mulTableGenerator}
	staticTabbleGens[1] = []TableGenerator{addTableGenerator, mulTableGenerator}
	// GKR circuit:
	c := NewCircuit(bGs, gates, transitionFuncs, staticTabbleGens)

	// hL, h' or hR, h'
	inputs := make([]fr.Element, 4)
	inputs[0].SetUint64(uint64(1))
	inputs[1].SetUint64(uint64(3))
	inputs[2].SetUint64(uint64(2))
	inputs[3].SetUint64(uint64(4))

	a := c.GenerateAssignment(inputs)
	inputsV := append([]fr.Element{}, inputs...)
	outputsV := a.LayerAsBKTWithCopy(2).Table

	p := NewProver(c, a)

	proof := p.Prove(1)

	v := NewVerifier(1, c)
	validity := v.Verify(proof, outputsV, inputsV)

	assert.Equal(
		t,
		validity,
		true,
		"Proof invalid.",
	)

	actualValues := make([][]fr.Element, 3)
	// actualValues =	[
	//						[1, 2, 3, 4],
	//						[3, 2, 7, 12],
	//						[5, 6, 19, 84]
	//					]
	actualValues[0] = make([]fr.Element, 4)
	actualValues[0][0].SetUint64(uint64(1))
	actualValues[0][1].SetUint64(uint64(3))
	actualValues[0][2].SetUint64(uint64(2))
	actualValues[0][3].SetUint64(uint64(4))
	actualValues[1] = make([]fr.Element, 4)
	actualValues[1][0].SetUint64(uint64(3))
	actualValues[1][1].SetUint64(uint64(7))
	actualValues[1][2].SetUint64(uint64(2))
	actualValues[1][3].SetUint64(uint64(12))
	actualValues[2] = make([]fr.Element, 4)
	actualValues[2][0].SetUint64(uint64(5))
	actualValues[2][1].SetUint64(uint64(19))
	actualValues[2][2].SetUint64(uint64(6))
	actualValues[2][3].SetUint64(uint64(84))

	assert.Equal(
		t,
		a.values,
		actualValues,
		"Proof invalid.",
	)
}
