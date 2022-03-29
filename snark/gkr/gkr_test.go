package gkr

import (
	"fmt"
	"testing"
	"time"

	"github.com/consensys/gkr-mimc/circuit"
	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gkr-mimc/examples"
	"github.com/consensys/gkr-mimc/gkr"
	polyFr "github.com/consensys/gkr-mimc/poly"
	poly "github.com/consensys/gkr-mimc/snark/polynomial"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type GKRMimcTestCircuit struct {
	Circuit       circuit.Circuit
	Proof         Proof
	QInitialPrime []frontend.Variable
	Inputs        []poly.MultiLin
	Output        poly.MultiLin
}

func AllocateGKRMimcTestCircuit(bN int) GKRMimcTestCircuit {
	exampleCircuit := examples.MimcCircuit()
	return GKRMimcTestCircuit{
		Circuit:       exampleCircuit,
		Proof:         AllocateProof(bN, exampleCircuit),
		QInitialPrime: make([]frontend.Variable, bN),
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
	qInitialPrime []fr.Element,
) {
	c.Proof.Assign(proof)
	for i := range qInitialPrime {
		c.QInitialPrime[i] = qInitialPrime[i]
	}

	for i := range inputs {
		c.Inputs[i].Assign(inputs[i])
	}
	c.Output.Assign(outputs)
}

func (c *GKRMimcTestCircuit) Define(cs frontend.API) error {
	c.Proof.AssertValid(cs, c.Circuit, c.QInitialPrime, c.Inputs, c.Output)
	return nil
}

func TestGkrCircuit(t *testing.T) {

	for bn := 0; bn < 12; bn++ {

		mimcCircuit := AllocateGKRMimcTestCircuit(bn)

		// Attempt to compile the circuit
		_, err := frontend.Compile(ecc.BN254, backend.GROTH16, &mimcCircuit)
		if err != nil {
			panic(err)
		}

		// Create witness values
		c := examples.MimcCircuit()
		inputs := []polyFr.MultiLin{
			common.RandomFrArray(1 << bn),
			common.RandomFrArray(1 << bn),
		}
		qPrime := common.RandomFrArray(bn)

		a := c.Assign(inputs...)
		outputs := a[93].DeepCopy()
		gkrProof := gkr.Prove(c, a, qPrime)

		err = gkr.Verify(c, gkrProof, inputs, outputs, qPrime)
		if err != nil {
			panic(err)
		}

		// Assigns the witness
		witness := AllocateGKRMimcTestCircuit(bn)
		witness.Assign(gkrProof, inputs, outputs, qPrime)

		err = test.IsSolved(&mimcCircuit, &witness, ecc.BN254, backend.GROTH16)
		if err != nil {
			panic(err)
		}

		polyFr.DumpLarge(a...)
	}

}

func BenchmarkMimcCircuit(b *testing.B) {
	// This will run the benchmark until, a SIGKILL happens
	// Or there is enough memory to run 32M hashes (=> impossible)
	for bn := 0; bn < 26; bn++ {

		fmt.Printf("bN = %v\n", bn)

		mimcCircuit := AllocateGKRMimcTestCircuit(bn)
		// Attempt to compile the circuit
		r1cs, _ := frontend.Compile(ecc.BN254, backend.GROTH16, &mimcCircuit)

		inte, sec, publ := r1cs.GetNbVariables()

		fmt.Printf("Nb constraints = %v\n", r1cs.GetNbConstraints())
		fmt.Printf("Nb constraints = int %v sec %v pub %v\n", inte, sec, publ)

		// Create witness values
		c := examples.MimcCircuit()
		inputs := []polyFr.MultiLin{
			common.RandomFrArray(1 << bn),
			common.RandomFrArray(1 << bn),
		}
		qPrime := common.RandomFrArray(bn)

		// Assignment - Benchmark
		t := time.Now()
		assignment := c.Assign(inputs...)
		fmt.Printf("gkr assignment took %v ms\n", time.Since(t).Milliseconds())

		// Keeps the output for later assignment : not sure if actually needed
		outputs := assignment[93].DeepCopyLarge()
		t = time.Now()
		proof := gkr.Prove(c, assignment, qPrime)
		fmt.Printf("gkr prover took %v ms\n", time.Since(t).Milliseconds())

		// Assigns the values
		witness := AllocateGKRMimcTestCircuit(bn)
		t = time.Now()
		witness.Assign(proof, inputs, outputs, qPrime)
		fmt.Printf("post gkr assignment took %v ms\n", time.Since(t).Milliseconds())

		pk, _ := groth16.DummySetup(r1cs)

		t = time.Now()
		w, _ := frontend.NewWitness(&witness, ecc.BN254)
		_, err := groth16.Prove(r1cs, pk, w)
		if err != nil {
			panic(err)
		}
		fmt.Printf("gnark prover took %v ms\n", time.Since(t).Milliseconds())
		polyFr.DumpLarge(assignment...)
	}
}
