module github.com/consensys/gkr-mimc

go 1.16

require (
	github.com/consensys/gnark v0.5.1
	github.com/consensys/gnark-crypto v0.5.3
	github.com/pkg/profile v1.5.0
	github.com/stretchr/testify v1.7.0
	golang.org/x/crypto v0.0.0-20210322153248-0c34fe9e7dc2
)

replace github.com/consensys/gnark v0.5.1 => ./pkg/gnark
