package examples

import (
	"runtime"
)

var nCore uint

func init() {
	initProcs()
}

func initProcs() {
	nCore = uint(runtime.GOMAXPROCS(0))
}
