package circuit

import (
	"gkr-mimc/common"
	"gkr-mimc/polynomial"

	"github.com/consensys/gurvy/bn256/fr"
)

// Wire represent a single connexion between a gate,
// its output and its inputs
type Wire struct {
	L, R, O int
	Gate    Gate
}

// Layer describes how a layer feeds its inputs
type Layer struct {
	Wires []Wire
}

// BGOutputs return the log-size of the input layer of the layer
func (l *Layer) BGOutputs() int {
	res := 0
	for _, wire := range l.Wires {
		if res < wire.O {
			res = wire.O
		}
	}
	return common.Log2Ceil(res + 1)
}

// BGInputs return the log-size of the input layer of the layer
func (l *Layer) BGInputs() int {
	res := 0
	for _, wire := range l.Wires {
		if res < wire.L {
			res = wire.L
		}
		if res < wire.R {
			res = wire.R
		}
	}
	return common.Log2Ceil(res + 1)
}

// Gates returns a deduplicated list of gates used by this layer
func (l *Layer) Gates() []Gate {
	gates := make(map[string]Gate)
	res := []Gate{}
	for i, wire := range l.Wires {
		if _, ok := gates[wire.Gate.ID()]; !ok {
			res = append(res, wire.Gate)
		}
	}
}

// GetStaticTable returns the prefolded static tables
func (l *Layer) GetStaticTable(q []fr.Element) []polynomial.BookKeepingTable {

}
