# Krypto2
These practical excersices are part of an advanced crypto lecture.


# Excersices

### 1.1 Universal Forgery of RSA Signatures:
(a) Generate your own 3000-bit RSA key. Output all RSA key parameters used.

(b) Implement the universal forgery of RSA signatures. Choose an arbitrary message for this. In the universal forgery, take on both the role of the attacker and the signer (oracle). Verify using the RSA verification algorithm that the RSA signatures computed in this way are verified correctly.

### 1.2 DSA Signatures:
(a) Implement DSA key generation. Output all DSA key parameters used.
Note: Use the algorithm from Appendix A.2.1 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf to determine a generator.

(b) Implement the DSA signature algorithm using the SHA-256 hash function. Sign randomly chosen messages with the DSA signature algorithm and verify that the verification algorithm correctly verifies the signatures.

(c) Create two DSA signatures using the same random number r. Calculate the private DSA key based on these two DSA signatures.