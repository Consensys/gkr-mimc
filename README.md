# GKR

## Optimizations

We can get away with far fewer multiplications in the combinator.
- We have to run a sumcheck for 
        V_{i+1}(q', q) 
            = sum_{hR, hL, h'}
                Eq(q', h') * (
                    Copy(q, hL, hR) * V_i(h', hL) 
                    +
                    Cipher(q, hL, hR) * (V_i(h', hR) + (V_i(h', hL) + K_i) ^ 7)
                )
- variables are eliminated in that order

|variables| hR | hL | h' |
|---|---|---|---|
|**Size**| bG | bG | bN |
|**Degree**| 2 | 8 | 8 |

- since bG = 1, in the \sum_{hR, hL} part involing 4 terms, only one can give something nonzero for Copy(q, hL, hR) and similarly only one can give something nonzero for Cipher(q, hL, hR)
- when eliminating hR first, it is of note that the seventh power (V_i(h', hL) + K_i) ^ 7 need only be computed once;
- after elimination of hR and hL, the book-keeping tables Cipher and Copy are reduced to scalars Ci and Co.
- we can leverage this to compute the relevant sums more efficiently. We will need two 9-tuples of accumulators:
    + one for Eq(q', h') * V_i(h', hL)  for 
    + one for Eq(q', h') * [(V_i(h', hR) + (V_i(h', hL) + K_i) ^ 7)]  
- and then combine these results using a multiplication by Co and Ci respectively to get the total sums
- implicitely we are thus using different combinator functions for the various stages of the summation. 