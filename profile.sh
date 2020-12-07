#!/bin/bash

go test -c ./src/sumcheck/...

go build main.go

# # Have valgrind profile criterion running our benchmark for 10 seconds
valgrind --tool=callgrind \
         --dump-instr=yes \
         --collect-jumps=yes \
         --simulate-cache=yes \
         ./main

# # valgrind outputs a callgrind.out.<pid>. We can analyze this with kcachegrind
# kcachegrind