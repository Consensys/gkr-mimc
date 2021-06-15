package gkr

import (
	"fmt"
	"gkr-mimc/circuit"
	"gkr-mimc/common"
	"gkr-mimc/examples"
	"gkr-mimc/gkr"
	"gkr-mimc/snark/polynomial"
	"runtime"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16""
	"github.com/consensys/gnark/frontend"
)

type GKRMimcTestCircuit struct {
	Circuit                 Circuit
	Proof                   Proof
	QInitial, QInitialprime []frontend.Variable
	VInput, VOutput         polynomial.MultilinearByValues
}

func AllocateGKRMimcTestCircuit(bN int) GKRMimcTestCircuit {
	circuit := CreateMimcCircuit()
	return GKRMimcTestCircuit{
		Circuit:       circuit,
		Proof:         AllocateProof(bN, circuit),
		QInitial:      []frontend.Variable{},
		QInitialprime: make([]frontend.Variable, bN),
		VInput:        polynomial.AllocateMultilinear(bN + 1),
		VOutput:       polynomial.AllocateMultilinear(bN),
	}
}

func (c *GKRMimcTestCircuit) Assign(
	proof gkr.Proof,
	inputs [][]fr.Element,
	outputs [][]fr.Element,
	qInitialprime []fr.Element,
) {
	c.Proof.Assign(proof)
	for i := range qInitialprime {
		c.QInitialprime[i].Assign(qInitialprime[i])
	}
	c.VInput.AssignFromChunkedBKT(inputs)
	c.VOutput.AssignFromChunkedBKT(outputs)
}

func (c *GKRMimcTestCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	c.Proof.AssertValid(cs, c.Circuit, c.QInitial, c.QInitialprime, c.VInput, c.VOutput)
	return nil
}

func TestMimcCircuit(t *testing.T) {
	bN := 2
	assert := groth16.NewAssert(t)

	var (
		r1cs frontend.CS
		err  error
	)

	{
		mimcCircuit := AllocateGKRMimcTestCircuit(bN)
		// Attempt to compile the circuit
		r1cs, err = frontend.Compile(ecc.BN254, &mimcCircuit)
		assert.NoError(err)
	}

	// Generate the witness values by running the prover
	var witness GKRMimcTestCircuit

	{
		// Creates the assignments values
		nativeCircuit := examples.CreateMimcCircuit()
		inputs := common.RandomFrDoubleSlice(1, 2*(1<<bN))
		assignment := nativeCircuit.Assign(inputs, 1)
		outputs := assignment.Values[91]
		prover := gkr.NewProver(nativeCircuit, assignment)
		proof := prover.Prove(1)
		qInitialprime, _ := gkr.GetInitialQPrimeAndQ(bN, 0)

		// Assigns the values
		witness = AllocateGKRMimcTestCircuit(bN)
		witness.Assign(proof, inputs, outputs, qInitialprime)
	}

	assert.SolvingSucceeded(r1cs, &witness)
	// Takes 200sec on my laptop
	// assert.ProverSucceeded(r1cs, &witness)
}

func BenchmarkMimcCircuit(b *testing.B) {
	bN := common.GetBN()
	nChunk := common.GetNChunks()
	inputsChunkSize := 2 * (1 << bN) / nChunk
	nCore := runtime.GOMAXPROCS(0)

	fmt.Printf("bN = %v, nChunk = %v, nCore = %v \n", bN, nChunk, nCore)

	var (
		r1cs r1cs.R1CS
	)

	{
		mimcCircuit := AllocateGKRMimcTestCircuit(bN)
		// Attempt to compile the circuit
		r1cs, _ = frontend.Compile(ecc.BN254, &mimcCircuit)
	}

	fmt.Printf("Nb constraints = %v\n", r1cs.GetNbConstraints())

	// Generate the witness values by running the prover
	var witness GKRMimcTestCircuit

	{
		// Creates the assignments values
		var (
			proof      gkr.Proof
			assignment circuit.Assignment
			outputs    [][]fr.Element
		)

		nativeCircuit := examples.CreateMimcCircuit()
		qInitialprime, _ := gkr.GetInitialQPrimeAndQ(bN, 0)
		inputs := common.RandomFrDoubleSlice(nChunk, inputsChunkSize)

		b.Run("Assignment generation for GKR Prover", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				assignment = nativeCircuit.Assign(inputs, nCore)
				outputs = assignment.Values[91]
			}
		})

		b.Run("GKR Prover", func(b *testing.B) {
			b.ResetTimer()
			b.StopTimer()
			for i := 0; i < b.N; i++ {
				prover := gkr.NewProver(nativeCircuit, assignment)
				b.StartTimer()
				proof = prover.Prove(nCore)
				b.StopTimer()
			}
		})

		// Assigns the values
		b.Run("Gnark circuit assignment", func(b *testing.B) {
			b.StopTimer()
			for i := 0; i < b.N; i++ {
				witness = AllocateGKRMimcTestCircuit(bN)
				b.StartTimer()
				witness.Assign(proof, inputs, outputs, qInitialprime)
				b.StopTimer()
			}
		})

	}

	pk, _ := groth16.DummySetup(r1cs)
	b.Run("Gnark prover", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = groth16.Prove(r1cs, pk, &witness)
		}
	})
}
