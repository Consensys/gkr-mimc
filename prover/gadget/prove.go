package gadget

import (
	"math/big"
	"runtime"

	"github.com/consensys/gkr-mimc/common"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark/notinternal/backend/bn254/cs"
	"github.com/consensys/gnark/notinternal/backend/bn254/groth16"
	"github.com/consensys/gnark/notinternal/utils"
)

// Extend proof for GKR-enabled SNARK
type Proof struct {
	Ar, Krs           bn254.G1Affine
	Bs                bn254.G2Affine
	KrsGkrPriv        bn254.G1Affine
	InitialRandomness fr.Element
}

// Solve and compute the proof
func Prove(r1cs *R1CS, pk *ProvingKey, assignment *Circuit) (*Proof, error) {
	solution, err := assignment.Solve(*r1cs)
	if err != nil {
		return nil, err
	}

	proof, err := ComputeProof(r1cs, pk, solution, assignment.Gadget.proof)
	if err != nil {
		return nil, err
	}

	return proof, nil
}

// Compute the proof
func ComputeProof(
	r1cs *R1CS,
	pk *ProvingKey, solution Solution,
	// Computed during the solving
	proof *Proof,
) (*Proof, error) {

	proof.InitialRandomness = solution.Wires[1]

	// By now, the Gkr part of the proof should be processed
	common.Assert(proof != nil, "Passed an empty proof to the prover")
	common.Assert(proof.KrsGkrPriv != bn254.G1Affine{}, "The proof misses the GkrPriv")

	// Get the number of public variables
	// _, _, pub := r1cs.r1cs.GetNbVariables()

	// Takes a subslice and convert to fr.Element
	subSlice := func(array []fr.Element, indices []int, offset int) []fr.Element {
		res := make([]fr.Element, len(indices))
		for i, idx := range indices {
			res[i] = array[idx+offset]
			// Also set the result in regular from
			res[i].FromMont()
		}
		return res
	}

	// Deduplicate and separate the non gkr inputs
	// As the GKR one where already processed by the Hint
	privNotGkrVars := subSlice(solution.Wires, r1cs.privNotGkrVarID, 0)
	var krsNotGkr bn254.G1Affine
	krsNotGkr.MultiExp(pk.privKNotGkr, privNotGkrVars, ecc.MultiExpConfig{})

	// Will perform all the computations beside the one involving `K`
	grothProof, err := ComputeGroth16Proof(&r1cs.r1cs, &pk.pk,
		solution.A, solution.B, solution.C, solution.Wires)
	if err != nil {
		panic(err)
	}

	// Complete our proof with the result of groth16
	proof.Ar = grothProof.Ar
	proof.Bs = grothProof.Bs

	// Processes the non-GKR priv part of the multiexp.
	var KrsPrivNotGkr bn254.G1Affine
	KrsPrivNotGkr.MultiExp(pk.privKNotGkr, privNotGkrVars, ecc.MultiExpConfig{})

	// Complete the Krs part with the part we calculated
	proof.Krs.Add(&grothProof.Krs, &KrsPrivNotGkr)

	return proof, err
}

// Modified SNARK prover: we additionally passes a puncturedVersion of the values
func ComputeGroth16Proof(r1cs *cs.R1CS, pk *groth16.ProvingKey, a, b, c, wireValues []fr.Element) (*Proof, error) {
	// Changes the capacity of a vector of fr.Element
	// Panic if the input capacity is below the length of the slice
	setCapacity := func(vec *[]fr.Element, newCap int) {
		res := make([]fr.Element, len(*vec), newCap)
		copy(res, *vec)
		*vec = res

	}

	// Increase the capacity of a, b, c
	setCapacity(&a, int(pk.Domain.Cardinality))
	setCapacity(&b, int(pk.Domain.Cardinality))
	setCapacity(&c, int(pk.Domain.Cardinality))

	// set the wire values in regular form
	utils.Parallelize(len(wireValues), func(start, end int) {
		for i := start; i < end; i++ {
			wireValues[i].FromMont()
		}
	})

	// H (witness reduction / FFT part)
	var h []fr.Element
	chHDone := make(chan struct{}, 1)
	go func() {
		h = computeH(a, b, c, &pk.Domain)
		a = nil
		b = nil
		c = nil
		chHDone <- struct{}{}
	}()

	// we need to copy and filter the wireValues for each multi exp
	// as pk.G1.A, pk.G1.B and pk.G2.B may have (a significant) number of point at infinity
	var wireValuesA, wireValuesB []fr.Element
	chWireValuesA, chWireValuesB := make(chan struct{}, 1), make(chan struct{}, 1)

	go func() {
		wireValuesA = make([]fr.Element, len(wireValues)-int(pk.NbInfinityA))
		for i, j := 0, 0; j < len(wireValuesA); i++ {
			if pk.InfinityA[i] {
				continue
			}
			wireValuesA[j] = wireValues[i]
			j++
		}
		close(chWireValuesA)
	}()
	go func() {
		wireValuesB = make([]fr.Element, len(wireValues)-int(pk.NbInfinityB))
		for i, j := 0, 0; j < len(wireValuesB); i++ {
			if pk.InfinityB[i] {
				continue
			}
			wireValuesB[j] = wireValues[i]
			j++
		}
		close(chWireValuesB)
	}()

	// sample random r and s
	var r, s big.Int
	var _r, _s, _kr fr.Element
	if _, err := _r.SetRandom(); err != nil {
		return nil, err
	}
	if _, err := _s.SetRandom(); err != nil {
		return nil, err
	}
	_kr.Mul(&_r, &_s).Neg(&_kr)

	_r.FromMont()
	_s.FromMont()
	_kr.FromMont()
	_r.ToBigInt(&r)
	_s.ToBigInt(&s)

	// computes r[δ], s[δ], kr[δ]
	deltas := bn254.BatchScalarMultiplicationG1(&pk.G1.Delta, []fr.Element{_r, _s, _kr})

	proof := &Proof{}
	var bs1, ar bn254.G1Jac

	n := runtime.NumCPU()

	chBs1Done := make(chan error, 1)
	computeBS1 := func() {
		<-chWireValuesB
		if _, err := bs1.MultiExp(pk.G1.B, wireValuesB, ecc.MultiExpConfig{NbTasks: n / 2}); err != nil {
			chBs1Done <- err
			close(chBs1Done)
			return
		}
		bs1.AddMixed(&pk.G1.Beta)
		bs1.AddMixed(&deltas[1])
		chBs1Done <- nil
	}

	chArDone := make(chan error, 1)
	computeAR1 := func() {
		<-chWireValuesA
		if _, err := ar.MultiExp(pk.G1.A, wireValuesA, ecc.MultiExpConfig{NbTasks: n / 2}); err != nil {
			chArDone <- err
			close(chArDone)
			return
		}
		ar.AddMixed(&pk.G1.Alpha)
		ar.AddMixed(&deltas[0])
		proof.Ar.FromJacobian(&ar)
		chArDone <- nil
	}

	chKrsDone := make(chan error, 1)
	computeKRS := func() {
		// we could NOT split the Krs multiExp in 2, and just append pk.G1.K and pk.G1.Z
		// however, having similar lengths for our tasks helps with parallelism

		var krs, krs2, p1 bn254.G1Jac
		chKrs2Done := make(chan error, 1)
		go func() {
			_, err := krs2.MultiExp(pk.G1.Z, h, ecc.MultiExpConfig{NbTasks: n / 2})
			chKrs2Done <- err
		}()

		// WE REMOVED THE Krs multiplication here, as it is simpler to handle it separately in our case
		// ---------------

		// if _, err := krs.MultiExp(pk.G1.K, puncturedPrivWiresValues, ecc.MultiExpConfig{NbTasks: n / 2}); err != nil {
		// 	chKrsDone <- err
		// 	return
		// }

		// ---------------

		krs.AddMixed(&deltas[2])
		n := 3
		for n != 0 {
			select {
			case err := <-chKrs2Done:
				if err != nil {
					chKrsDone <- err
					return
				}
				krs.AddAssign(&krs2)
			case err := <-chArDone:
				if err != nil {
					chKrsDone <- err
					return
				}
				p1.ScalarMultiplication(&ar, &s)
				krs.AddAssign(&p1)
			case err := <-chBs1Done:
				if err != nil {
					chKrsDone <- err
					return
				}
				p1.ScalarMultiplication(&bs1, &r)
				krs.AddAssign(&p1)
			}
			n--
		}

		proof.Krs.FromJacobian(&krs)
		chKrsDone <- nil
	}

	computeBS2 := func() error {
		// Bs2 (1 multi exp G2 - size = len(wires))
		var Bs, deltaS bn254.G2Jac

		nbTasks := n
		if nbTasks <= 16 {
			// if we don't have a lot of CPUs, this may artificially split the MSM
			nbTasks *= 2
		}
		<-chWireValuesB
		if _, err := Bs.MultiExp(pk.G2.B, wireValuesB, ecc.MultiExpConfig{NbTasks: nbTasks}); err != nil {
			return err
		}

		deltaS.FromAffine(&pk.G2.Delta)
		deltaS.ScalarMultiplication(&deltaS, &s)
		Bs.AddAssign(&deltaS)
		Bs.AddMixed(&pk.G2.Beta)

		proof.Bs.FromJacobian(&Bs)
		return nil
	}

	// wait for FFT to end, as it uses all our CPUs
	<-chHDone

	// schedule our proof part computations
	go computeKRS()
	go computeAR1()
	go computeBS1()
	if err := computeBS2(); err != nil {
		return nil, err
	}

	// wait for all parts of the proof to be computed.
	if err := <-chKrsDone; err != nil {
		return nil, err
	}

	return proof, nil

}

func computeH(a, b, c []fr.Element, domain *fft.Domain) []fr.Element {
	// H part of Krs
	// Compute H (hz=ab-c, where z=-2 on ker X^n+1 (z(x)=x^n-1))
	// 	1 - _a = ifft(a), _b = ifft(b), _c = ifft(c)
	// 	2 - ca = fft_coset(_a), ba = fft_coset(_b), cc = fft_coset(_c)
	// 	3 - h = ifft_coset(ca o cb - cc)

	n := len(a)

	// add padding to ensure input length is domain cardinality
	padding := make([]fr.Element, int(domain.Cardinality)-n)
	a = append(a, padding...)
	b = append(b, padding...)
	c = append(c, padding...)
	n = len(a)

	domain.FFTInverse(a, fft.DIF, 0)
	domain.FFTInverse(b, fft.DIF, 0)
	domain.FFTInverse(c, fft.DIF, 0)

	domain.FFT(a, fft.DIT, 1)
	domain.FFT(b, fft.DIT, 1)
	domain.FFT(c, fft.DIT, 1)

	var minusTwoInv fr.Element
	minusTwoInv.SetUint64(2)
	minusTwoInv.Neg(&minusTwoInv).
		Inverse(&minusTwoInv)

	// h = ifft_coset(ca o cb - cc)
	// reusing a to avoid unecessary memalloc
	utils.Parallelize(n, func(start, end int) {
		for i := start; i < end; i++ {
			a[i].Mul(&a[i], &b[i]).
				Sub(&a[i], &c[i]).
				Mul(&a[i], &minusTwoInv)
		}
	})

	// ifft_coset
	domain.FFTInverse(a, fft.DIF, 1)

	utils.Parallelize(len(a), func(start, end int) {
		for i := start; i < end; i++ {
			a[i].FromMont()
		}
	})

	return a
}
