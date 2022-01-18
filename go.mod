module github.com/consensys/gkr-mimc

go 1.16

require (
	github.com/AlexandreBelling/gnark v0.5.1
	github.com/consensys/gnark-crypto v0.5.4-0.20211222202820-aee0c136fb9f
	github.com/kr/pretty v0.2.1 // indirect
	github.com/pkg/profile v1.5.0
	github.com/stretchr/testify v1.7.0
	golang.org/x/crypto v0.0.0-20210322153248-0c34fe9e7dc2
	golang.org/x/sys v0.0.0-20211019181941-9d821ace8654 // indirect
)

replace github.com/AlexandreBelling/gnark v0.5.1 => ./pkg/gnark
