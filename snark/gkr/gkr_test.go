package gkr

import (
	"testing"

	"github.com/consensys/gkr-mimc/circuit"
	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gkr-mimc/examples"
	"github.com/consensys/gkr-mimc/gkr"
	polyFr "github.com/consensys/gkr-mimc/poly"
	poly "github.com/consensys/gkr-mimc/snark/polynomial"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type GKRMimcTestCircuit struct {
	Circuit       circuit.Circuit
	Proof         Proof
	QInitialprime []frontend.Variable
	Inputs        []poly.MultiLin
	Output        poly.MultiLin
}

func AllocateGKRMimcTestCircuit(bN int) GKRMimcTestCircuit {
	circuit := examples.Mimc()
	return GKRMimcTestCircuit{
		Circuit:       circuit,
		Proof:         AllocateProof(bN, circuit),
		QInitialprime: make([]frontend.Variable, bN),
		Output:        poly.AllocateMultilinear(bN),
		Inputs: []poly.MultiLin{
			poly.AllocateMultilinear(bN),
			poly.AllocateMultilinear(bN),
		},
	}
}

func (c *GKRMimcTestCircuit) Assign(
	proof gkr.Proof,
	inputs []polyFr.MultiLin,
	outputs polyFr.MultiLin,
	qInitialprime []fr.Element,
) {
	c.Proof.Assign(proof)
	for i := range qInitialprime {
		c.QInitialprime[i] = qInitialprime[i]
	}

	for i := range inputs {
		c.Inputs[i].Assign(inputs[i])
	}
	c.Output.Assign(outputs)
}

func (c *GKRMimcTestCircuit) Define(cs frontend.API) error {
	c.Proof.AssertValid(cs, c.Circuit, c.QInitialprime, c.Inputs, c.Output)
	return nil
}

func TestMimcCircuit(t *testing.T) {

	bn := 2

	mimcCircuit := AllocateGKRMimcTestCircuit(bn)

	// Attempt to compile the circuit
	_, err := frontend.Compile(ecc.BN254, backend.GROTH16, &mimcCircuit)
	if err != nil {
		panic(err)
	}

	// Create witness values
	c := examples.Mimc()
	inputs := []polyFr.MultiLin{
		common.RandomFrArray(1 << bn),
		common.RandomFrArray(1 << bn),
	}
	qPrime := common.RandomFrArray(bn)

	a := c.Assign(inputs...)
	outputs := a[93].DeepCopyLarge()
	gkrProof := gkr.Prove(c, a, qPrime)

	// Assigns the witness
	witness := AllocateGKRMimcTestCircuit(bn)
	witness.Assign(gkrProof, inputs, outputs, qPrime)

	test.IsSolved(&mimcCircuit, &witness, ecc.BN254, backend.GROTH16)

}

// func BenchmarkMimcCircuit(b *testing.B) {
// 	bN := common.GetBN()
// 	nChunk := common.GetNChunks()
// 	inputsChunkSize := 2 * (1 << bN) / nChunk
// 	nCore := runtime.GOMAXPROCS(0)

// 	fmt.Printf("bN = %v, nChunk = %v, nCore = %v \n", bN, nChunk, nCore)

// 	mimcCircuit := AllocateGKRMimcTestCircuit(bN)
// 	// Attempt to compile the circuit
// 	r1cs, _ := frontend.Compile(ecc.BN254, backend.GROTH16, &mimcCircuit)

// 	fmt.Printf("Nb constraints = %v\n", r1cs.GetNbConstraints())

// 	// Generate the witness values by running the prover
// 	var witness GKRMimcTestCircuit

// 	// Creates the assignments values
// 	var (
// 		proof      gkr.Proof
// 		assignment circuit.Assignment
// 		outputs    [][]fr.Element
// 	)

// 	nativeCircuit := examples.CreateMimcCircuit()
// 	qInitialprime, _ := gkr.GetInitialQPrimeAndQ(bN, 0)
// 	inputs := common.RandomFrDoubleSlice(nChunk, inputsChunkSize)

// 	b.Run("Assignment generation for GKR Prover", func(b *testing.B) {
// 		for i := 0; i < b.N; i++ {
// 			assignment = nativeCircuit.Assign(inputs, nCore)
// 			outputs = assignment.Values[91]
// 		}
// 	})

// 	b.Run("GKR Prover", func(b *testing.B) {
// 		b.ResetTimer()
// 		b.StopTimer()
// 		for i := 0; i < b.N; i++ {
// 			prover := gkr.NewProver(nativeCircuit, assignment)
// 			b.StartTimer()
// 			proof = prover.Prove(nCore)
// 			b.StopTimer()
// 		}
// 	})

// 	// Assigns the values
// 	b.Run("Gnark circuit assignment", func(b *testing.B) {
// 		b.StopTimer()
// 		for i := 0; i < b.N; i++ {
// 			witness = AllocateGKRMimcTestCircuit(bN)
// 			b.StartTimer()
// 			witness.Assign(proof, inputs, outputs, qInitialprime)
// 			b.StopTimer()
// 		}
// 	})

// 	pk, _ := groth16.DummySetup(r1cs)
// 	b.Run("Gnark prover", func(b *testing.B) {
// 		for i := 0; i < b.N; i++ {
// 			w, _ := frontend.NewWitness(&witness, ecc.BN254)
// 			_, _ = groth16.Prove(r1cs, pk, w)
// 		}
// 	})
// }
