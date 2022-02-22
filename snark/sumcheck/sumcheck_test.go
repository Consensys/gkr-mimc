package sumcheck

import (
	"testing"

	"github.com/consensys/gkr-mimc/circuit"
	"github.com/consensys/gkr-mimc/poly"
	"github.com/consensys/gkr-mimc/sumcheck"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type SumcheckCircuit struct {
	InitialClaim   []frontend.Variable
	Proof          Proof
	ExpectedQPrime []frontend.Variable
}

func AllocateSumcheckCircuit(bN, nInstance int, gate circuit.Gate) SumcheckCircuit {
	return SumcheckCircuit{
		Proof:          AllocateProof(bN, gate),
		ExpectedQPrime: make([]frontend.Variable, bN),
		InitialClaim:   make([]frontend.Variable, nInstance),
	}
}

func (scc *SumcheckCircuit) Define(cs frontend.API) error {
	hPrime, _, _ := scc.Proof.AssertValid(cs, scc.InitialClaim)

	for i := range hPrime {
		cs.AssertIsEqual(hPrime[i], scc.ExpectedQPrime[i])
	}

	return nil
}

func (scc *SumcheckCircuit) Assign(
	proof sumcheck.Proof,
	initialClaim []fr.Element,
	expectedQPrime []fr.Element,
) error {
	scc.Proof.Assign(proof)

	for i := range initialClaim {
		scc.InitialClaim[i] = initialClaim[i]
	}

	for i := range expectedQPrime {
		scc.ExpectedQPrime[i] = expectedQPrime[i]
	}

	return nil
}

func genericTest(t *testing.T, X []poly.MultiLin, claims []fr.Element, qs [][]fr.Element, gate circuit.Gate) {
	proof, expectedQPrime, _ := sumcheck.Prove(X, qs, claims, gate)
	circ := AllocateSumcheckCircuit(len(qs[0]), len(claims), gate)

	_, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circ)
	if err != nil {
		panic(err)
	}

	witness := AllocateSumcheckCircuit(len(qs[0]), len(claims), gate)
	witness.Assign(proof, claims, expectedQPrime)

	err = test.IsSolved(&circ, &witness, ecc.BN254, backend.GROTH16)
	if err != nil {
		panic(err)
	}

}

func TestSumcheckCircuit(t *testing.T) {

	for bn := 0; bn < 15; bn++ {
		X, claims, qs, gate := sumcheck.InitializeCipherGateInstance(bn)
		genericTest(t, X, claims, qs, gate)

		ninstance := 5
		X, claims, qs, gate = sumcheck.InitializeMultiInstance(bn, ninstance)
		genericTest(t, X, claims, qs, gate)
	}

}
