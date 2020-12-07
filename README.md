# GKR

gkr-mimc is a POC-grade gnark gadget to accelerate the proving time of MiMc hash computations. It can take a batch of hash inputs and output a batch of hash outputs along with a gkr proof that can be verified from inside a SNARK circuit.

It is a toy implementation of this [post](https://ethresear.ch/t/using-gkr-inside-a-snark-to-reduce-the-cost-of-hash-verification-down-to-3-constraints/7550) for MiMC. Over time, it will into a more generic library, that can support other use cases than MiMC.