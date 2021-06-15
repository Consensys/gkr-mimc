package common

import (
	"gkr-mimc/hash"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// GetChallenge returns a interaction challenge
func GetChallenge(challengeSeed []fr.Element) fr.Element {
	return hash.MimcHash(challengeSeed)
}
