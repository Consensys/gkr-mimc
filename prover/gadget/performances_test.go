package gadget

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/AlexandreBelling/gnark/backend"
	"github.com/AlexandreBelling/gnark/backend/groth16"
	"github.com/AlexandreBelling/gnark/frontend"
	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gkr-mimc/snark/hash"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func BenchmarkCircuitWithGKR(b *testing.B) {
	n := 1 << 15
	chunkSize := 1 << 15
	benchCircuitWithGkr(n, chunkSize, b)
	benchCircuitBaseline(n, b)
}

type CircuitBaseline struct {
	X []frontend.Variable
}

type CircuitWithGkr struct {
	X []frontend.Variable
}

func AllocateCircuitBaseline(n int) CircuitBaseline {
	return CircuitBaseline{X: make([]frontend.Variable, n)}
}

func AllocateCircuitWithGkr(n int) CircuitUsingGkr {
	return &CircuitWithGkr{X: make([]frontend.Variable, n)}
}

func (c *CircuitBaseline) Define(cs frontend.API) error {
	for _, x := range c.X {
		_ = hash.MimcHash(cs, x)
	}
	return nil
}

func (c *CircuitWithGkr) Define(cs frontend.API, gadget *GkrGadget) error {
	for _, x := range c.X {
		_ = gadget.UpdateHasher(cs, frontend.Variable(0), x)
	}
	return nil
}

func AssignCircuitBaseline(n int) CircuitBaseline {
	res := CircuitBaseline{X: make([]frontend.Variable, n)}
	var rnd fr.Element
	rnd.SetRandom()
	for i := range res.X {
		res.X[i] = rnd
	}
	return res
}

func AssignCircuitWithGkr(n int) CircuitWithGkr {
	res := CircuitWithGkr{X: make([]frontend.Variable, n)}
	var rnd fr.Element
	rnd.SetRandom()
	for i := range res.X {
		res.X[i] = rnd
	}
	return res
}

func benchCircuitWithGkr(n int, chunkSize int, b *testing.B) {
	circ := AllocateCircuitWithGkr(n)
	circuit := WrapCircuitUsingGkr(circ, WithMinChunkSize(chunkSize), WithNCore(runtime.NumCPU()))
	r1cs, err := circuit.Compile()

	if err != nil {
		panic(fmt.Sprintf("Could not compile = %v", err))
	}

	pk, _, err := DummySetup(&r1cs)

	if err != nil {
		panic(fmt.Sprintf("Could not setup = %v", err))
	}

	ass := AssignCircuitWithGkr(n)
	assignment := WrapCircuitUsingGkr(&ass, WithMinChunkSize(chunkSize), WithNCore(runtime.NumCPU()))
	assignment.Assign()

	b.Run("Circuit-with-GKR-benchmark", func(b *testing.B) {
		common.ProfileTrace(b, true, true, func() {
			for i := 0; i < b.N; i++ {
				_, err = Prove(&r1cs, &pk, &assignment)
				common.Assert(err == nil, "Prover failed %v", err)
			}
		})
	})
}

func benchCircuitBaseline(n int, b *testing.B) {
	circuit := AllocateCircuitBaseline(n)
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)

	if err != nil {
		panic(fmt.Sprintf("Could not compile = %v", err))
	}

	pk, err := groth16.DummySetup(r1cs)

	if err != nil {
		panic(fmt.Sprintf("Could not setup = %v", err))
	}

	assignment := AssignCircuitBaseline(n)

	b.Run("Baseline circuit", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err = groth16.Prove(r1cs, pk, &assignment)
			common.Assert(err == nil, "Prover failed %v", err)
		}
	})
}
