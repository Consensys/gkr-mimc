package common

import (
	"gkr-mimc/hash"

	"github.com/consensys/gurvy/bn256/fr"
)

// GetChallenge returns a interaction challenge
func GetChallenge(challengeSeed []fr.Element) fr.Element {
	return hash.MimcHash(challengeSeed)
}
