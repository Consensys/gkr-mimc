package gkr

import (
	"fmt"
	"gkr-mimc/circuit/polynomial"
	"gkr-mimc/common"
	"gkr-mimc/examples"
	"gkr-mimc/gkr"
	"os"
	"runtime"
	"strconv"
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/r1cs"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
	"github.com/consensys/gurvy/bn256/fr"
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
	inputs []fr.Element,
	outputs []fr.Element,
	qInitialprime []fr.Element,
) {
	c.Proof.Assign(proof)
	for i := range qInitialprime {
		c.QInitialprime[i].Assign(qInitialprime[i])
	}
	c.VInput.Assign(common.FrToGenericArray(inputs))
	c.VOutput.Assign(common.FrToGenericArray(outputs))
}

func (c *GKRMimcTestCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	c.Proof.AssertValid(cs, c.Circuit, c.QInitial, c.QInitialprime, c.VInput, c.VOutput)
	return nil
}

func TestMimcCircuit(t *testing.T) {
	bN := 2
	assert := groth16.NewAssert(t)

	var (
		r1cs r1cs.R1CS
		err  error
	)

	{
		mimcCircuit := AllocateGKRMimcTestCircuit(bN)
		// Attempt to compile the circuit
		r1cs, err = frontend.Compile(gurvy.BN256, &mimcCircuit)
		assert.NoError(err)
	}

	// Generate the witness values by running the prover
	var witness GKRMimcTestCircuit

	{
		// Creates the assignments values
		nativeCircuit := examples.CreateMimcCircuit()
		inputs := common.RandomFrArray(2 * (1 << bN))
		assignment := nativeCircuit.GenerateAssignment(inputs)
		outputs := assignment.LayerAsBKTNoCopy(91).Table
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
	bN, _ := strconv.Atoi(os.Getenv("BN_GKR"))
	nChunk := 1 << common.Log2(runtime.GOMAXPROCS(0))

	fmt.Printf("bN = %v, nChunk = %v \n", bN, nChunk)

	var (
		r1cs r1cs.R1CS
	)

	{
		mimcCircuit := AllocateGKRMimcTestCircuit(bN)
		// Attempt to compile the circuit
		r1cs, _ = frontend.Compile(gurvy.BN256, &mimcCircuit)
	}

	fmt.Printf("Nb constraints = %v\n", r1cs.GetNbConstraints())

	// Generate the witness values by running the prover
	var witness GKRMimcTestCircuit

	{
		// Creates the assignments values
		var (
			proof      gkr.Proof
			assignment gkr.Assignment
			outputs    []fr.Element
		)

		nativeCircuit := examples.CreateMimcCircuit()
		qInitialprime, _ := gkr.GetInitialQPrimeAndQ(bN, 0)
		inputs := common.RandomFrArray(2 * (1 << bN))

		b.Run("Assignment generation for GKR Prover", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				assignment = nativeCircuit.GenerateAssignment(inputs)
				outputs = assignment.LayerAsBKTNoCopy(91).Table
			}
		})

		b.Run("GKR Prover", func(b *testing.B) {
			b.ResetTimer()
			b.StopTimer()
			for i := 0; i < b.N; i++ {
				prover := gkr.NewProver(nativeCircuit, assignment)
				b.StartTimer()
				proof = prover.Prove(nChunk)
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
