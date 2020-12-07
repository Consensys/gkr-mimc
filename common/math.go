package common

// Min returns the minimum of two numbers
func Min(a int, b int) int {
	if a <= b {
		return a
	}
	return b
}

// Max returns the maximum of two number
func Max(a int, b int) int {
	if a >= b {
		return a
	}
	return b
}

// Log2 computes n where the leading bit of a is at position n
func Log2(a int) int {

	res := 0
	for i := a; i > 1; i /= 2 {
		res++
	}
	return res
}
