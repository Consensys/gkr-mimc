// Copyright 2020 ConsenSys Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by gnark DO NOT EDIT

package groth16

import (
	"github.com/consensys/gnark-crypto/ecc"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"

	"errors"
	"fmt"
	bn254witness "github.com/consensys/gkr-mimc/prover/backend/bn254/witness"
	"io"

	"text/template"
)

var (
	errPairingCheckFailed         = errors.New("pairing doesn't match")
	errCorrectSubgroupCheckFailed = errors.New("points in the proof are not in the correct subgroup")
)

// Verify verifies a proof with given VerifyingKey and publicWitness
func Verify(proof *Proof, vk *VerifyingKey, publicWitness bn254witness.Witness) error {

	if len(publicWitness) != (len(vk.G1.K) - 1) {
		return fmt.Errorf("invalid witness size, got %d, expected %d (public - ONE_WIRE)", len(publicWitness), len(vk.G1.K)-1)
	}

	// check that the points in the proof are in the correct subgroup
	if !proof.isValid() {
		return errCorrectSubgroupCheckFailed
	}

	var doubleML curve.GT
	chDone := make(chan error, 1)

	// compute (eKrsδ, eArBs)
	go func() {
		var errML error
		doubleML, errML = curve.MillerLoop([]curve.G1Affine{proof.Krs, proof.Ar}, []curve.G2Affine{vk.G2.deltaNeg, proof.Bs})
		chDone <- errML
		close(chDone)
	}()

	// compute e(Σx.[Kvk(t)]1, -[γ]2)
	var kSum curve.G1Jac
	if _, err := kSum.MultiExp(vk.G1.K[1:], publicWitness, ecc.MultiExpConfig{ScalarsMont: true}); err != nil {
		return err
	}
	kSum.AddMixed(&vk.G1.K[0])
	var kSumAff curve.G1Affine
	kSumAff.FromJacobian(&kSum)

	right, err := curve.MillerLoop([]curve.G1Affine{kSumAff}, []curve.G2Affine{vk.G2.gammaNeg})
	if err != nil {
		return err
	}

	// wait for (eKrsδ, eArBs)
	if err := <-chDone; err != nil {
		return err
	}

	right = curve.FinalExponentiation(&right, &doubleML)
	if !vk.e.Equal(&right) {
		return errPairingCheckFailed
	}
	return nil
}

// ExportSolidity writes a solidity Verifier contract on provided writer
// while this uses an audited template https://github.com/appliedzkp/semaphore/blob/master/contracts/sol/verifier.sol
// audit report https://github.com/appliedzkp/semaphore/blob/master/audit/Audit%20Report%20Summary%20for%20Semaphore%20and%20MicroMix.pdf
// this is an experimental feature and gnark solidity generator as not been thoroughly tested
func (vk *VerifyingKey) ExportSolidity(w io.Writer) error {
	helpers := template.FuncMap{
		"sub": func(a, b int) int {
			return a - b
		},
	}

	tmpl, err := template.New("").Funcs(helpers).Parse(solidityTemplate)
	if err != nil {
		return err
	}

	// execute template
	return tmpl.Execute(w, vk)
}
