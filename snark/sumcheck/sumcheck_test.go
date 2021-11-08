package sumcheck

import (
	"testing"

	"github.com/consensys/gkr-mimc/sumcheck"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type SumcheckCircuit struct {
	InitialClaim   frontend.Variable
	Proof          Proof
	ExpectedQL     []frontend.Variable
	ExpectedQR     []frontend.Variable
	ExpectedQPrime []frontend.Variable
}

func AllocateSumcheckCircuit(bN, bG, degHL, degHR, degHPrime int) SumcheckCircuit {
	return SumcheckCircuit{
		Proof:          AllocateProof(bN, bG, degHL, degHR, degHPrime),
		ExpectedQL:     make([]frontend.Variable, bG),
		ExpectedQR:     make([]frontend.Variable, bG),
		ExpectedQPrime: make([]frontend.Variable, bN),
	}
}

func (scc *SumcheckCircuit) Define(curveID ecc.ID, cs frontend.API) error {
	hR, hL, hPrime, _ := scc.Proof.AssertValid(cs, scc.InitialClaim, 1)
	for i := range hR {
		cs.AssertIsEqual(hL[i], scc.ExpectedQL[i])
		cs.AssertIsEqual(hR[i], scc.ExpectedQR[i])
	}

	for i := range hPrime {
		cs.AssertIsEqual(hPrime[i], scc.ExpectedQPrime[i])
	}

	return nil
}

func TestSumcheckCircuit(t *testing.T) {

	var bN, bG, degHL, degHR, degHPrime = 4, 1, 2, 8, 8
	assert := test.NewAssert(t)

	// Attempts to compile the circuit
	scc := AllocateSumcheckCircuit(bN, bG, degHL, degHR, degHPrime)
	// r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &scc)
	// assert.NoError(err)

	// Runs a test sumcheck prover to get witness values
	scProver := sumcheck.InitializeProverForTests(bN)
	firstClaim := scProver.GetClaim()
	scVer := sumcheck.Verifier{}
	proof, expectedQPrime, expectedQR, expectedQL, _ := scProver.Prove()
	valid, _, _, _, _ := scVer.Verify(firstClaim, proof, bN, bG)

	assert.True(valid, "Sumcheck verifier refused")

	witness := AllocateSumcheckCircuit(bN, bG, degHL, degHR, degHPrime)
	witness.InitialClaim.Assign(firstClaim)
	witness.Proof.Assign(proof)

	for i := range expectedQL {
		witness.ExpectedQL[i].Assign(expectedQL[i])
		witness.ExpectedQR[i].Assign(expectedQR[i])

	}

	for i := range expectedQPrime {
		witness.ExpectedQPrime[i].Assign(expectedQPrime[i])
	}

	assert.SolvingSucceeded(&scc, &witness)
	assert.ProverSucceeded(&scc, &witness)
}
