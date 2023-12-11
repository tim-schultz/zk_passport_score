# zk_passport_score
Compute a score for a Gitcoin Passport in a ZK fashion

# Links
- https://noir-lang.org/
  - verifying secp256k1 signature: https://noir-lang.org/dev/standard_library/cryptographic_primitives/ecdsa_sig_verification/
- https://github.com/sambarnes/noir-by-example
- https://github.com/noir-lang/awesome-noir

# Calculating Score in Noir

Public inputs:
- an array of stamp hashes

Private inputs (the VC):
- array of VCs
    - given that validating the VCs in noir is difficult, we can instead pass in:
        - array of dids (did coresponding to each stamp)
        - array of providers
        - signature (secp256k1) computed by the issuer to prove validity of the tuple (did, provider, hash)
- signature (secp256k1) to prove ownership of the DIDs
    - not required in first iteration of POC


Circuit configuration / setup:
- provider weights

Verify that the user qualifies

**Step 1**
- validate all the dids
  - we need a proof that the user owns this did, hence a signature created with the eTH address of the did is required
  - but we should also use some sort of nonce

**Step 2**
- iterate over the list of providers
- validate the VC (or the secp256k1 for the tuple (did, provider, hash) )
  - check that this signature was created by the issuer (IAM)
- sum up weights
- allow each provider only once


# TODO
- [ ] create first iteration of circuit (basic, not all verification needed in circuit)
- [ ] create UI for proof generation
- [ ] create UI for proof verification generation
- [ ] implement end-to-end flow
- [ ] implement validations in circuit
- [ ] implement nullfier / deduplication
